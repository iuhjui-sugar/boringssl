/* Copyright (c) 2018, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include <openssl/bytestring.h>
#include <openssl/ssl.h>

#include "../internal.h"
#include "handshake_util.h"
#include "test_config.h"
#include "test_state.h"

using namespace bssl;

namespace {

bool HandbackReady(SSL *ssl, int ret) {
  return ret < 0 && SSL_get_error(ssl, ret) == SSL_ERROR_HANDBACK;
}

bool Handshaker(const TestConfig *config, int rfd, int wfd,
                       Span<const uint8_t> input, int control) {
  UniquePtr<SSL_CTX> ctx = config->SetupCtx(/*old_ctx=*/nullptr);
  if (!ctx) {
    return false;
  }

  UniquePtr<SSL> ssl_handshake = config->NewSSL(
      ctx.get(), nullptr, false, nullptr);
  SSL *ssl = ssl_handshake.get();

  // Set |O_NONBLOCK| in order to signal the proxy to send us more data when the
  // handshake hits |SSL_ERROR_WANT_READ|.
  assert(fcntl(rfd, F_SETFL, O_NONBLOCK) == 0);
  SSL_set_rfd(ssl, rfd);
  SSL_set_wfd(ssl, wfd);

  CBS cbs, handoff;
  CBS_init(&cbs, input.data(), input.size());
  if (!CBS_get_asn1_element(&cbs, &handoff, CBS_ASN1_SEQUENCE) ||
      !DeserializeContextState(&cbs, ctx.get()) ||
      !SetTestState(ssl, TestState::Deserialize(&cbs, ctx.get())) ||
      !GetTestState(ssl) ||
      !SSL_apply_handoff(ssl, handoff)) {
    fprintf(stderr, "Handoff application failed.\n");
    return false;
  }

  int ret = 0;
  for (;;) {
    ret = CheckIdempotentError("SSL_do_handshake", ssl,
                               [&]() -> int { return SSL_do_handshake(ssl); });
    if (SSL_get_error(ssl, ret) == SSL_ERROR_WANT_READ) {
      char msg = kControlMsgWantRead;
      if (write(control, &msg, 1) != 1 ||
          read(control, &msg, 1) != 1 ||
          msg != kControlMsgWriteCompleted) {
        fprintf(stderr, "read via proxy failed\n");
        return false;
      }
      continue;
    }
    if (!config->async || !RetryAsync(ssl, ret)) {
      break;
    }
  }

  if (!HandbackReady(ssl, ret)) {
    ERR_print_errors_fp(stderr);
    return false;
  }

  ScopedCBB output;
  CBB handback;
  Array<uint8_t> bytes;
  if (!CBB_init(output.get(), 1024) ||
      !CBB_add_u24_length_prefixed(output.get(), &handback) ||
      !SSL_serialize_handback(ssl, &handback) ||
      !SerializeContextState(ssl->ctx.get(), output.get()) ||
      !GetTestState(ssl)->Serialize(output.get()) ||
      !CBBFinishArray(output.get(), &bytes)) {
    fprintf(stderr, "Handback serialisation failed.\n");
    return false;
  }

  char msg = kControlMsgHandback;
  if (write(control, &msg, 1) != 1 ||
      write(control, bytes.data(), bytes.size()) != (int)bytes.size()) {
    perror("write");
    return false;
  }
  return true;
}

}  // namespace

int main(int argc, char **argv) {
  TestConfig initial_config, resume_config, retry_config;
  if (!ParseConfig(argc, argv, &initial_config, &resume_config,
                   &retry_config)) {
    return 2;
  }
  const TestConfig *config = initial_config.handshaker_resume ? &resume_config : &initial_config;

  uint8_t handoff[1024 * 1024];
  int len = read(kFdControl, handoff, sizeof(handoff));
  if (len == -1) {
    _exit(2);
  }
  if (!Handshaker(config, kFdProxyToHandshaker, kFdHandshakerToProxy,
                  {handoff, (size_t)len}, kFdControl)) {
    char msg = kControlMsgError;
    if (write(kFdControl, &msg, 1) != 1) {
      return 3;
    }
    return 1;
  }
  return 0;
}
