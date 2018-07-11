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

#include "test_state.h"

#include <openssl/ssl.h>

#include "../../crypto/internal.h"
#include "../internal.h"

using namespace bssl;

static CRYPTO_once_t g_once = CRYPTO_ONCE_INIT;
static int g_state_index = 0;
// Some code treats the zero time special, so initialize the clock to a
// non-zero time.
static timeval g_clock = { 1234, 1234 };

static void TestStateExFree(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                            int index, long argl, void *argp) {
  delete ((TestState *)ptr);
}

static void init_once() {
  g_state_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, TestStateExFree);
  if (g_state_index < 0) {
    abort();
  }
}

struct timeval *GetClock() {
  CRYPTO_once(&g_once, init_once);
  return &g_clock;
}

void AdvanceClock(unsigned seconds) {
  CRYPTO_once(&g_once, init_once);
  g_clock.tv_sec += seconds;
}

bool SetTestState(SSL *ssl, std::unique_ptr<TestState> state) {
  CRYPTO_once(&g_once, init_once);
  // |SSL_set_ex_data| takes ownership of |state| only on success.
  if (SSL_set_ex_data(ssl, g_state_index, state.get()) == 1) {
    state.release();
    return true;
  }
  return false;
}

TestState *GetTestState(const SSL *ssl) {
  CRYPTO_once(&g_once, init_once);
  return (TestState *)SSL_get_ex_data(ssl, g_state_index);
}

static void ssl_ctx_add_session(SSL_SESSION *session, void *void_param) {
  SSL_CTX *ctx = reinterpret_cast<SSL_CTX *>(void_param);
  UniquePtr<SSL_SESSION> new_session = SSL_SESSION_dup(
      session, SSL_SESSION_INCLUDE_NONAUTH | SSL_SESSION_INCLUDE_TICKET);
  if (new_session != nullptr) {
    SSL_CTX_add_session(ctx, new_session.get());
  }
}

void CopySessions(SSL_CTX *dst, const SSL_CTX *src) {
  lh_SSL_SESSION_doall_arg(src->sessions, ssl_ctx_add_session, dst);
}

static void push_session(SSL_SESSION *session, void *arg) {
  auto s = reinterpret_cast<std::vector<SSL_SESSION *> *>(arg);
  s->push_back(session);
}

bool TestState::Serialize(SSL_CTX *ctx, CBB *cbb) const {
  CBB out;
  uint16_t version = 0;

  // Do the stuff from |ctx| first.
  CBB ctx_sessions;
  if (!CBB_add_u24_length_prefixed(cbb, &out) || !CBB_add_u16(&out, version) ||
      !CBB_add_asn1(&out, &ctx_sessions, CBS_ASN1_SEQUENCE)) {
    return false;
  }
  std::vector<SSL_SESSION *> sessions;
  lh_SSL_SESSION_doall_arg(ctx->sessions, push_session, &sessions);
  for (const auto &sess : sessions) {
    if (!ssl_session_serialize(sess, &ctx_sessions)) {
      return false;
    }
  }
  uint8_t keys[48];
  CBB ticket_keys;
  if (!SSL_CTX_get_tlsext_ticket_keys(ctx, &keys, sizeof(keys)) ||
      !CBB_add_u8_length_prefixed(&out, &ticket_keys) ||
      !CBB_add_bytes(&ticket_keys, keys, sizeof(keys))) {
    return false;
  }

  // Now do the |TestState| stuff.
  CBB pending, text;
  if (/* async_bio is handled specially */
      channel_id != nullptr ||
      packeted_bio != nullptr ||
      !CBB_add_u8(&out, cert_ready) ||
      session != nullptr ||
      !CBB_add_u24_length_prefixed(&out, &pending) ||
      (pending_session &&
       !ssl_session_serialize(pending_session.get(), &pending)) ||
      !CBB_add_u8(&out, early_callback_called) ||
      handshake_done != false ||
      // By pure luck, |private_key| is installed only after the handshake
      // begins, and not needed thereafter.  Otherwise, we would have to
      // serialize it.
      !private_key_result.empty() ||
      private_key_retries != 0 ||
      got_new_session != false ||
      new_session != nullptr ||
      !CBB_add_u8(&out, ticket_decrypt_done) ||
      !CBB_add_u8(&out, alpn_select_done) ||
      !CBB_add_u8(&out, is_resume) ||
      !CBB_add_u8(&out, early_callback_ready) ||
      custom_verify_ready != false ||
      !CBB_add_u16_length_prefixed(&out, &text) ||
      !CBB_add_bytes(
          &text, reinterpret_cast<const uint8_t *>(msg_callback_text.data()),
          msg_callback_text.length()) ||
      !CBB_add_u8(&out, msg_callback_ok) ||
      cert_verified != false) {
    return false;
  }

  return CBB_flush(cbb);
}

std::unique_ptr<TestState> TestState::Deserialize(CBS *cbs, SSL_CTX *out_ctx) {
  // A word about versioning: one day, we will add a new test that requires
  // additional state to be serialized.  That test will fail when one of the two
  // components (shim, handshaker) is out of date.  And so we will need a way to
  // blacklist such new tests.
  //
  // Mere additions to the test state serialization format can be handled by
  // tacking new stuff onto the end.  More complex refactorings can make use of
  // the version field.

  CBS in, sessions;
  uint16_t version;
  if (!CBS_get_u24_length_prefixed(cbs, &in) || !CBS_get_u16(&in, &version) ||
      version != 0 || !CBS_get_asn1(&in, &sessions, CBS_ASN1_SEQUENCE)) {
    return nullptr;
  }
  while (CBS_len(&sessions)) {
    UniquePtr<SSL_SESSION> session =
        SSL_SESSION_parse(&sessions, out_ctx->x509_method, out_ctx->pool);
    if (!session) {
      return nullptr;
    }
    ssl_ctx_add_session(session.get(), out_ctx);
  }
  CBS ticket_keys;
  if (!CBS_get_u8_length_prefixed(&in, &ticket_keys) ||
      !SSL_CTX_set_tlsext_ticket_keys(out_ctx, CBS_data(&ticket_keys),
                                      CBS_len(&ticket_keys))) {
    return nullptr;
  }

  std::unique_ptr<TestState> out_state(new TestState());
  CBS pending_session, text;
  uint8_t cert_ready, early_callback_called, ticket_decrypt_done,
      alpn_select_done, is_resume, early_callback_ready, msg_callback_ok;
  if (!CBS_get_u8(&in, &cert_ready) ||
      !CBS_get_u24_length_prefixed(&in, &pending_session) ||
      !CBS_get_u8(&in, &early_callback_called) ||
      !CBS_get_u8(&in, &ticket_decrypt_done) ||
      !CBS_get_u8(&in, &alpn_select_done) ||
      !CBS_get_u8(&in, &is_resume) ||
      !CBS_get_u8(&in, &early_callback_ready) ||
      !CBS_get_u16_length_prefixed(&in, &text) ||
      !CBS_get_u8(&in, &msg_callback_ok)) {
    return nullptr;
  }
  if (CBS_len(&pending_session)) {
    out_state->pending_session = SSL_SESSION_parse(
        &pending_session, out_ctx->x509_method, out_ctx->pool);
    if (!out_state->pending_session) {
      return nullptr;
    }
  }
  out_state->cert_ready = cert_ready;
  out_state->early_callback_called = early_callback_called;
  out_state->ticket_decrypt_done = ticket_decrypt_done;
  out_state->alpn_select_done = alpn_select_done;
  out_state->is_resume = is_resume;
  out_state->early_callback_ready = early_callback_ready;
  out_state->msg_callback_ok = msg_callback_ok;
  out_state->msg_callback_text = std::string(
      reinterpret_cast<const char *>(CBS_data(&text)), CBS_len(&text));

  // No check for CBS_len(in) == 0, in order to allow additional data to be
  // tacked on to the end.

  return out_state;
}

bool MoveTestState(SSL *dest, SSL *src) {
  ScopedCBB out;
  Array<uint8_t> serialized;
  if (!CBB_init(out.get(), 512) ||
      !GetTestState(src)->Serialize(src->ctx.get(), out.get()) ||
      !CBBFinishArray(out.get(), &serialized)) {
    return false;
  }
  CBS in;
  CBS_init(&in, serialized.data(), serialized.size());
  if (!SetTestState(dest, TestState::Deserialize(&in, dest->ctx.get())) ||
      !GetTestState(dest)) {
    return false;
  }
  GetTestState(dest)->async_bio = GetTestState(src)->async_bio;
  GetTestState(src)->async_bio = nullptr;
  return true;
}
