/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * ECC cipher suite support in OpenSSL originally written by
 * Vipul Gupta and Sumit Gupta of Sun Microsystems Laboratories.
 *
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

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
  state_tls13,
  state_done,
};

static enum ssl_hs_wait_t dtls1_get_hello_verify_request(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  SSLMessage msg;
  if (!ssl->method->get_message(ssl, &msg)) {
    return ssl_hs_read_message;
  }

  if (msg.type != DTLS1_MT_HELLO_VERIFY_REQUEST) {
    ssl->d1->send_cookie = false;
    return ssl_hs_ok;
  }

  CBS hello_verify_request = msg.body, cookie;
  uint16_t server_version;
  if (!CBS_get_u16(&hello_verify_request, &server_version) ||
      !CBS_get_u8_length_prefixed(&hello_verify_request, &cookie) ||
      CBS_len(&cookie) > sizeof(ssl->d1->cookie) ||
      CBS_len(&hello_verify_request) != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return ssl_hs_error;
  }

  OPENSSL_memcpy(ssl->d1->cookie, CBS_data(&cookie), CBS_len(&cookie));
  ssl->d1->cookie_len = CBS_len(&cookie);

  ssl->d1->send_cookie = true;
  ssl->method->next_message(ssl);
  return ssl_hs_ok;
}

/* ssl_get_client_disabled sets |*out_mask_a| and |*out_mask_k| to masks of
 * disabled algorithms. */
static void ssl_get_client_disabled(SSL *ssl, uint32_t *out_mask_a,
                                    uint32_t *out_mask_k) {
  *out_mask_a = 0;
  *out_mask_k = 0;

  /* PSK requires a client callback. */
  if (ssl->psk_client_callback == NULL) {
    *out_mask_a |= SSL_aPSK;
    *out_mask_k |= SSL_kPSK;
  }
}

static int parse_server_version(SSL_HANDSHAKE *hs, uint16_t *out,
                                const SSLMessage &msg) {
  SSL *const ssl = hs->ssl;
  if (msg.type != SSL3_MT_SERVER_HELLO &&
      msg.type != SSL3_MT_HELLO_RETRY_REQUEST) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
    return 0;
  }

  CBS server_hello = msg.body;
  if (!CBS_get_u16(&server_hello, out)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return 0;
  }

  /* The server version may also be in the supported_versions extension if
   * applicable. */
  if (msg.type != SSL3_MT_SERVER_HELLO || *out != TLS1_2_VERSION) {
    return 1;
  }

  uint8_t sid_length;
  if (!CBS_skip(&server_hello, SSL3_RANDOM_SIZE) ||
      !CBS_get_u8(&server_hello, &sid_length) ||
      !CBS_skip(&server_hello, sid_length + 2 /* cipher_suite */ +
                1 /* compression_method */)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return 0;
  }

  /* The extensions block may not be present. */
  if (CBS_len(&server_hello) == 0) {
    return 1;
  }

  CBS extensions;
  if (!CBS_get_u16_length_prefixed(&server_hello, &extensions) ||
      CBS_len(&server_hello) != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return 0;
  }

  int have_supported_versions;
  CBS supported_versions;
  const SSL_EXTENSION_TYPE ext_types[] = {
    {TLSEXT_TYPE_supported_versions, &have_supported_versions,
     &supported_versions},
  };

  uint8_t alert = SSL_AD_DECODE_ERROR;
  if (!ssl_parse_extensions(&extensions, &alert, ext_types,
                            OPENSSL_ARRAY_SIZE(ext_types),
                            1 /* ignore unknown */)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
    return 0;
  }

  if (have_supported_versions &&
      (!CBS_get_u16(&supported_versions, out) ||
       CBS_len(&supported_versions) != 0)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return 0;
  }

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
  enum ssl_hs_wait_t wait = dtls1_get_hello_verify_request(hs);
  if (wait != ssl_hs_ok) {
    return wait;
  }

  if (ssl->d1->send_cookie) {
    hs->tls_state = state_send_client_hello;
  } else {
    hs->tls_state = state_read_server_hello;
  }
  return ssl_hs_ok;
}

static enum ssl_hs_wait_t do_read_server_hello(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  SSLMessage msg;
  if (!ssl->method->get_message(ssl, &msg)) {
    uint32_t err = ERR_peek_error();
    if (ERR_GET_LIB(err) == ERR_LIB_SSL &&
        ERR_GET_REASON(err) == SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE) {
      /* Add a dedicated error code to the queue for a handshake_failure alert
       * in response to ClientHello. This matches NSS's client behavior and
       * gives a better error on a (probable) failure to negotiate initial
       * parameters. Note: this error code comes after the original one.
       *
       * See https://crbug.com/446505. */
      OPENSSL_PUT_ERROR(SSL, SSL_R_HANDSHAKE_FAILURE_ON_CLIENT_HELLO);
      return ssl_hs_error;
    }
    return ssl_hs_read_message;
  }

  uint16_t server_version;
  if (!parse_server_version(hs, &server_version, msg)) {
    return ssl_hs_error;
  }

  if (!ssl_supports_version(hs, server_version)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNSUPPORTED_PROTOCOL);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_PROTOCOL_VERSION);
    return ssl_hs_error;
  }

  assert(ssl->s3->have_version == ssl->s3->initial_handshake_complete);
  if (!ssl->s3->have_version) {
    ssl->version = server_version;
    /* At this point, the connection's version is known and ssl->version is
     * fixed. Begin enforcing the record-layer version. */
    ssl->s3->have_version = 1;
  } else if (server_version != ssl->version) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_SSL_VERSION);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_PROTOCOL_VERSION);
    return ssl_hs_error;
  }

  if (ssl3_protocol_version(ssl) >= TLS1_3_VERSION) {
    hs->tls_state = state_done;
    hs->state = SSL_ST_TLS13;
    hs->do_tls13_handshake = tls13_client_handshake;
    return ssl_hs_ok;
  }

  if (hs->early_data_offered) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_VERSION_ON_EARLY_DATA);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_PROTOCOL_VERSION);
    return ssl_hs_error;
  }

  ssl_clear_tls13_state(hs);

  if (!ssl_check_message_type(ssl, msg, SSL3_MT_SERVER_HELLO)) {
    return ssl_hs_error;
  }

  CBS server_hello = msg.body, server_random, session_id;
  uint16_t cipher_suite;
  uint8_t compression_method;
  if (!CBS_skip(&server_hello, 2 /* version */) ||
      !CBS_get_bytes(&server_hello, &server_random, SSL3_RANDOM_SIZE) ||
      !CBS_get_u8_length_prefixed(&server_hello, &session_id) ||
      CBS_len(&session_id) > SSL3_SESSION_ID_SIZE ||
      !CBS_get_u16(&server_hello, &cipher_suite) ||
      !CBS_get_u8(&server_hello, &compression_method)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return ssl_hs_error;
  }

  /* Copy over the server random. */
  OPENSSL_memcpy(ssl->s3->server_random, CBS_data(&server_random),
                 SSL3_RANDOM_SIZE);

  /* TODO(davidben): Implement the TLS 1.1 and 1.2 downgrade sentinels once TLS
   * 1.3 is finalized and we are not implementing a draft version. */

  if (!ssl->s3->initial_handshake_complete && ssl->session != NULL &&
      ssl->session->session_id_length != 0 &&
      CBS_mem_equal(&session_id, ssl->session->session_id,
                    ssl->session->session_id_length)) {
    ssl->s3->session_reused = 1;
  } else {
    /* The session wasn't resumed. Create a fresh SSL_SESSION to
     * fill out. */
    ssl_set_session(ssl, NULL);
    if (!ssl_get_new_session(hs, 0 /* client */)) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
      return ssl_hs_error;
    }
    /* Note: session_id could be empty. */
    hs->new_session->session_id_length = CBS_len(&session_id);
    OPENSSL_memcpy(hs->new_session->session_id, CBS_data(&session_id),
                   CBS_len(&session_id));
  }

  const SSL_CIPHER *cipher = SSL_get_cipher_by_value(cipher_suite);
  if (cipher == NULL) {
    /* unknown cipher */
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNKNOWN_CIPHER_RETURNED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
    return ssl_hs_error;
  }

  /* The cipher must be allowed in the selected version and enabled. */
  uint32_t mask_a, mask_k;
  ssl_get_client_disabled(ssl, &mask_a, &mask_k);
  if ((cipher->algorithm_mkey & mask_k) || (cipher->algorithm_auth & mask_a) ||
      SSL_CIPHER_get_min_version(cipher) > ssl3_protocol_version(ssl) ||
      SSL_CIPHER_get_max_version(cipher) < ssl3_protocol_version(ssl) ||
      !sk_SSL_CIPHER_find(SSL_get_ciphers(ssl), NULL, cipher)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_CIPHER_RETURNED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
    return ssl_hs_error;
  }

  if (ssl->session != NULL) {
    if (ssl->session->ssl_version != ssl->version) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_OLD_SESSION_VERSION_NOT_RETURNED);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
      return ssl_hs_error;
    }
    if (ssl->session->cipher != cipher) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
      return ssl_hs_error;
    }
    if (!ssl_session_is_context_valid(ssl, ssl->session)) {
      /* This is actually a client application bug. */
      OPENSSL_PUT_ERROR(SSL,
                        SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
      return ssl_hs_error;
    }
  } else {
    hs->new_session->cipher = cipher;
  }
  hs->new_cipher = cipher;

  /* Now that the cipher is known, initialize the handshake hash and hash the
   * ServerHello. */
  if (!hs->transcript.InitHash(ssl3_protocol_version(ssl), hs->new_cipher) ||
      !ssl_hash_message(hs, msg)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
    return ssl_hs_error;
  }

  /* If doing a full handshake, the server may request a client certificate
   * which requires hashing the handshake transcript. Otherwise, the handshake
   * buffer may be released. */
  if (ssl->session != NULL ||
      !ssl_cipher_uses_certificate_auth(hs->new_cipher)) {
    hs->transcript.FreeBuffer();
  }

  /* Only the NULL compression algorithm is supported. */
  if (compression_method != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
    return ssl_hs_error;
  }

  /* TLS extensions */
  if (!ssl_parse_serverhello_tlsext(hs, &server_hello)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
    return ssl_hs_error;
  }

  /* There should be nothing left over in the record. */
  if (CBS_len(&server_hello) != 0) {
    /* wrong packet length */
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return ssl_hs_error;
  }

  if (ssl->session != NULL &&
      hs->extended_master_secret != ssl->session->extended_master_secret) {
    if (ssl->session->extended_master_secret) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_RESUMED_EMS_SESSION_WITHOUT_EMS_EXTENSION);
    } else {
      OPENSSL_PUT_ERROR(SSL, SSL_R_RESUMED_NON_EMS_SESSION_WITH_EMS_EXTENSION);
    }
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
    return ssl_hs_error;
  }

  ssl->method->next_message(ssl);

  if (ssl->session != NULL) {
    hs->state = SSL3_ST_CR_SESSION_TICKET_A;
  } else {
    hs->state = SSL3_ST_CR_CERT_A;
  }
  hs->tls_state = state_done;
  return ssl_hs_ok;
}

static enum ssl_hs_wait_t do_tls13(SSL_HANDSHAKE *hs) {
  int early_return = 0;
  if (tls13_handshake(hs, &early_return) <= 0) {
    return ssl_hs_early_wait;
  }

  if (early_return) {
    return ssl_hs_early_return;
  }

  hs->tls_state = state_done;
  hs->state = SSL3_ST_FINISH_CLIENT_HANDSHAKE;
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
        ret = do_read_server_hello(hs);
        break;
      case state_tls13:
        ret = do_tls13(hs);
        break;
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
