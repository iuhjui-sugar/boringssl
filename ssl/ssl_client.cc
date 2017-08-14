/* Copyright (c) 2017, Google Inc.
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

#include <openssl/ssl.h>

#include <assert.h>
#include <limits.h>
#include <string.h>

#include <utility>

#include <openssl/mem.h>
#include <openssl/rand.h>

#include "../crypto/internal.h"
#include "internal.h"


namespace bssl {

enum tls_client_hs_state_t {
  state_send_client_hello = 0,
  state_enter_early_data,
  state_read_hello_verify_request,
  state_read_server_hello,
  state_done,
};

static int dtls1_get_hello_verify_request(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  SSLMessage msg;
  int ret = ssl_read_message(ssl, &msg);
  if (ret <= 0) {
    return ret;
  }

  if (msg.type != DTLS1_MT_HELLO_VERIFY_REQUEST) {
    ssl->d1->send_cookie = false;
    return 1;
  }

  CBS hello_verify_request = msg.body, cookie;
  uint16_t server_version;
  if (!CBS_get_u16(&hello_verify_request, &server_version) ||
      !CBS_get_u8_length_prefixed(&hello_verify_request, &cookie) ||
      CBS_len(&cookie) > sizeof(ssl->d1->cookie) ||
      CBS_len(&hello_verify_request) != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return -1;
  }

  OPENSSL_memcpy(ssl->d1->cookie, CBS_data(&cookie), CBS_len(&cookie));
  ssl->d1->cookie_len = CBS_len(&cookie);

  ssl->d1->send_cookie = true;
  ssl->method->next_message(ssl);
  return 1;
}

static enum ssl_hs_wait_t do_send_client_hello(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;

  /* The handshake buffer is reset on every ClientHello. Notably, in DTLS, we
   * may send multiple ClientHellos if we receive HelloVerifyRequest. */
  if (!hs->transcript.Init()) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return ssl_hs_error;
  }

  /* Freeze the version range. */
  if (!ssl_get_version_range(ssl, &hs->min_version, &hs->max_version)) {
    return ssl_hs_error;
  }

  /* Always advertise the ClientHello version from the original maximum version,
   * even on renegotiation. The static RSA key exchange uses this field, and
   * some servers fail when it changes across handshakes. */
  if (SSL_is_dtls(hs->ssl)) {
    hs->client_version =
        hs->max_version >= TLS1_2_VERSION ? DTLS1_2_VERSION : DTLS1_VERSION;
  } else {
    hs->client_version =
        hs->max_version >= TLS1_2_VERSION ? TLS1_2_VERSION : hs->max_version;
  }

  /* If the configured session has expired or was created at a disabled
   * version, drop it. */
  if (ssl->session != NULL) {
    if (ssl->session->is_server ||
        !ssl_supports_version(hs, ssl->session->ssl_version) ||
        (ssl->session->session_id_length == 0 &&
         ssl->session->tlsext_ticklen == 0) ||
        ssl->session->not_resumable ||
        !ssl_session_is_time_valid(ssl, ssl->session)) {
      ssl_set_session(ssl, NULL);
    }
  }

  /* If resending the ClientHello in DTLS after a HelloVerifyRequest, don't
   * renegerate the client_random. The random must be reused. */
  if ((!SSL_is_dtls(ssl) || !ssl->d1->send_cookie) &&
      !RAND_bytes(ssl->s3->client_random, sizeof(ssl->s3->client_random))) {
    return ssl_hs_error;
  }

  /* Initialize a random session ID for the experimental TLS 1.3 variant
   * requiring a session id. */
  if (ssl->tls13_variant == tls13_experiment) {
    hs->session_id_len = sizeof(hs->session_id);
    if (!RAND_bytes(hs->session_id, hs->session_id_len)) {
      return ssl_hs_error;
    }
  }

  if (!ssl_write_client_hello(hs)) {
    return ssl_hs_error;
  }

  hs->tls_state = state_enter_early_data;
  return ssl_hs_flush;
}

static enum ssl_hs_wait_t do_enter_early_data(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;

  if (SSL_is_dtls(ssl) && !ssl->d1->send_cookie) {
    hs->tls_state = state_read_hello_verify_request;
    return ssl_hs_ok;
  }

  if (!hs->early_data_offered) {
    hs->tls_state = state_read_server_hello;
    return ssl_hs_ok;
  }

  if (!tls13_init_early_key_schedule(hs) ||
      !tls13_advance_key_schedule(hs, ssl->session->master_key,
                                  ssl->session->master_key_length) ||
      !tls13_derive_early_secrets(hs) ||
      !tls13_set_traffic_key(ssl, evp_aead_seal, hs->early_traffic_secret,
                             hs->hash_len)) {
    return ssl_hs_error;
  }

  /* Stash the early data session, so connection properties may be queried out
   * of it. */
  hs->in_early_data = 1;
  SSL_SESSION_up_ref(ssl->session);
  hs->early_session.reset(ssl->session);
  hs->can_early_write = 1;

  hs->tls_state = state_read_server_hello;
  return ssl_hs_early_return;
}

static enum ssl_hs_wait_t do_read_hello_verify_request(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;

  assert(SSL_is_dtls(ssl));
  if (dtls1_get_hello_verify_request(hs) <= 0) {
    return ssl_hs_read_message;
  }

  if (ssl->d1->send_cookie) {
    hs->tls_state = state_send_client_hello;
  } else {
    hs->tls_state = state_read_server_hello;
  }
  return ssl_hs_ok;
}

enum ssl_hs_wait_t tls_client_handshake(SSL_HANDSHAKE *hs) {
  while (hs->tls_state != state_done) {
    enum ssl_hs_wait_t ret = ssl_hs_error;
    enum tls_client_hs_state_t state =
        static_cast<enum tls_client_hs_state_t>(hs->tls_state);
    switch (state) {
      case state_send_client_hello:
        ret = do_send_client_hello(hs);
        break;
      case state_enter_early_data:
        ret = do_enter_early_data(hs);
        break;
      case state_read_hello_verify_request:
        ret = do_read_hello_verify_request(hs);
        break;
      case state_read_server_hello:
        hs->tls_state = state_done;
      case state_done:
        ret = ssl_hs_ok;
        break;
    }

    if (ret != ssl_hs_ok) {
      return ret;
    }
  }

  return ssl_hs_ok;
}

}
