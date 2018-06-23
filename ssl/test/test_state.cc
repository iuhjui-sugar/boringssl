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

int TestState::num_ddos_callbacks = 0;

static CRYPTO_once_t g_once = CRYPTO_ONCE_INIT;
static int g_state_index = 0;
static timeval g_clock;

static void TestStateExFree(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                            int index, long argl, void *argp) {
  delete ((TestState *)ptr);
}

static void init_once() {
  g_state_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, TestStateExFree);
  if (g_state_index < 0) {
    abort();
  }
  // Some code treats the zero time special, so initialize the clock to a
  // non-zero time.
  g_clock.tv_sec = 1234;
  g_clock.tv_usec = 1234;
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

bool MoveTestState(SSL *dest, SSL *src) {
  TestState *state = GetTestState(src);
  if (!SSL_set_ex_data(src, g_state_index, nullptr) ||
      !SSL_set_ex_data(dest, g_state_index, state)) {
    return false;
  }

  return true;
}

static void ssl_ctx_add_session(SSL_SESSION *session, void *void_param) {
  SSL_CTX *ctx = reinterpret_cast<SSL_CTX *>(void_param);
  bssl::UniquePtr<SSL_SESSION> new_session = bssl::SSL_SESSION_dup(
      session, SSL_SESSION_INCLUDE_NONAUTH | SSL_SESSION_INCLUDE_TICKET);
  if (new_session != nullptr) {
    SSL_CTX_add_session(ctx, new_session.get());
  }
}

void CopySessions(SSL_CTX *dst, const SSL_CTX *src) {
  lh_SSL_SESSION_doall_arg(src->sessions, ssl_ctx_add_session, dst);
}

bool SerializeTestState(const SSL *ssl, CBB *out) {
  uint8_t keys[48];
  if (!SSL_CTX_get_tlsext_ticket_keys(ssl->ctx, &keys, sizeof(keys))) {
    return false;
  }
  SSL_SESSION *pending = GetTestState(ssl)->pending_session.get();
  CBB ticket_keys, pending_session, ctx_sessions;
  if (!CBB_add_u8_length_prefixed(out, &ticket_keys) ||
      !CBB_add_bytes(&ticket_keys, keys, sizeof(keys)) ||
      !CBB_add_u24_length_prefixed(out, &pending_session) ||
      (pending && !bssl::ssl_session_serialize(pending, &pending_session)) ||
      !CBB_add_asn1(out, &ctx_sessions, CBS_ASN1_SEQUENCE)) {
    return false;
  }
  std::vector<SSL_SESSION *> sessions;
  lh_SSL_SESSION_doall_arg(
      ssl->ctx->sessions,
      [](SSL_SESSION *session, void *arg) {
        auto s = reinterpret_cast<std::vector<SSL_SESSION *> *>(arg);
        s->push_back(session);
      },
      &sessions);
  for (const auto &session : sessions) {
    if (!bssl::ssl_session_serialize(session, &ctx_sessions)) {
      return false;
    }
  }
  return CBB_flush(out);
}

bool SerializeTestState2(const TestState *state, CBB *out) {
  CBB text;
  bssl::Array<uint8_t> bytes;
  if (!CBB_add_u8(out, state->early_callback_called) ||
      !CBB_add_u8(out, state->msg_callback_ok) ||
      !CBB_add_u8(out, state->num_ddos_callbacks) ||
      !CBB_add_u16_length_prefixed(out, &text) ||
      !CBB_add_bytes(&text, (const uint8_t *)state->msg_callback_text.data(),
                     state->msg_callback_text.length())) {
    return false;
  }
  return CBB_flush(out);
}

bool DeserializeTestState2(CBS *in, TestState *out_state) {
  uint8_t early_callback_called, msg_callback_ok, num_ddos_callbacks;
  CBS msg_callback_text;
  if (!CBS_get_u8(in, &early_callback_called) ||
      !CBS_get_u8(in, &msg_callback_ok) ||
      !CBS_get_u8(in, &num_ddos_callbacks) ||
      !CBS_get_u16_length_prefixed(in, &msg_callback_text)) {
    return false;
  }

  out_state->early_callback_called = early_callback_called;
  out_state->msg_callback_ok = msg_callback_ok;
  out_state->num_ddos_callbacks = num_ddos_callbacks;
  out_state->msg_callback_text += std::string(
      (const char *)CBS_data(&msg_callback_text), CBS_len(&msg_callback_text));
  return true;
}

bool DeserializeTestState(CBS *in, TestState *out_state, SSL_CTX *out_ctx) {
  CBS cbs, handoff, ticket_keys;
  CBS pending_session, sessions;
  if (!CBS_get_u8_length_prefixed(in, &ticket_keys) ||
      !SSL_CTX_set_tlsext_ticket_keys(out_ctx, CBS_data(&ticket_keys),
                                      CBS_len(&ticket_keys)) ||
      !CBS_get_u24_length_prefixed(in, &pending_session) ||
      !CBS_get_asn1(in, &sessions, CBS_ASN1_SEQUENCE)) {
    return false;
  }
  if (CBS_len(&pending_session)) {
    out_state->pending_session = bssl::SSL_SESSION_parse(
        &pending_session, out_ctx->x509_method, out_ctx->pool);
    if (!out_state->pending_session) {
      return false;
    }
  }
  while (CBS_len(&sessions)) {
    bssl::UniquePtr<SSL_SESSION> session =
        bssl::SSL_SESSION_parse(&sessions, out_ctx->x509_method, out_ctx->pool);
    if (!session) {
      return false;
    }
    ssl_ctx_add_session(session.get(), out_ctx);
  }
  return true;
}
