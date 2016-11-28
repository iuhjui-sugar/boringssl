/* Copyright (c) 2016, Google Inc.
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

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include "../crypto/test/test_util.h"

struct GlobalState {
  GlobalState()
      : ctx(SSL_CTX_new(SSLv23_method())) {
    // We just want the context
  }

  ~GlobalState() {
    SSL_CTX_free(ctx);
  }

  SSL_CTX *const ctx;
};

static GlobalState g_state;

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
  SSL *ssl = SSL_new(g_state.ctx);

  // Parse in our session
  SSL_SESSION *session = SSL_SESSION_from_bytes(buf, len);

  // Give it to the context
  // TODO (rsloan): perform more sophisticated check here.
  SSL_set_session(ssl, session);

  // Re-encode it
  size_t re_encoded_len;
  uint8_t *re_encoded;
  if (!SSL_SESSION_to_bytes(session, &re_encoded, &re_encoded_len)) {
    fprintf(stderr, "SSL_SESSION_to_bytes failed\n");
    return 1;
  }

  // Verify the new encoding
  if (re_encoded_len != len ||
      memcmp(buf, re_encoded, len) != 0) {
    fprintf(stderr, "SSL_SESSION_to_bytes did not round-trip\n");
    hexdump(stderr, "Before: ", buf, len);
    hexdump(stderr, "After:  ", re_encoded, re_encoded_len);
    return 1;
  }

  // Free everything
  SSL_free(ssl);
  free(re_encoded);
  return 0;
}

