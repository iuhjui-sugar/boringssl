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

#include <openssl/ssl.h>

#include <assert.h>
#include <string.h>

#include <openssl/hkdf.h>
#include <openssl/rand.h>

#include "internal.h"

static int tls13_receive_client_hello(SSL *ssl, SSL_HS_MESSAGE msg) {
  int alert;
  STACK_OF(SSL_CIPHER) *ciphers = NULL;
  struct ssl_early_callback_ctx early_ctx;
  uint16_t client_wire_version;
  CBS client_random, session_id, cipher_suites, compression_methods;

  memset(&early_ctx, 0, sizeof(early_ctx));
  early_ctx.ssl = ssl;
  early_ctx.client_hello = msg.data;
  early_ctx.client_hello_len = msg.length;
  if (!ssl_early_callback_init(&early_ctx)) {
    alert = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_CLIENTHELLO_PARSE_FAILED);
    goto fatal_err;
  }

  CBS cbs;
  CBS_init(&cbs, msg.data, msg.length);

  if (!CBS_get_u16(&cbs, &client_wire_version) ||
      !CBS_get_bytes(&cbs, &client_random, SSL3_RANDOM_SIZE) ||
      !CBS_get_u8_length_prefixed(&cbs, &session_id) ||
      CBS_len(&session_id) > SSL_MAX_SSL_SESSION_ID_LENGTH) {
    alert = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    goto fatal_err;
  }

  uint16_t client_version = ssl->method->version_from_wire(client_wire_version);

  ssl->client_version = client_wire_version;

  uint16_t min_version, max_version;
  if (!ssl_get_version_range(ssl, &min_version, &max_version)) {
    alert = SSL_AD_PROTOCOL_VERSION;
    goto fatal_err;
  }

  if (!ssl->s3->have_version) {
    /* Select version to use */
    uint16_t version = client_version;
    if (version > max_version) {
      version = max_version;
    }
    if (version < min_version) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_UNSUPPORTED_PROTOCOL);
      alert = SSL_AD_PROTOCOL_VERSION;
      goto fatal_err;
    }
    ssl->version = ssl->method->version_to_wire(version);
    ssl->s3->enc_method = ssl3_get_enc_method(version);
    assert(ssl->s3->enc_method != NULL);
    /* At this point, the connection's version is known and |ssl->version| is
     * fixed. Begin enforcing the record-layer version. */
    ssl->s3->have_version = 1;
  } else if (client_version < ssl3_protocol_version(ssl)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_VERSION_NUMBER);
    alert = SSL_AD_PROTOCOL_VERSION;
    goto fatal_err;
  }

  /* Load the client random. */
  memcpy(ssl->s3->client_random, CBS_data(&client_random), SSL3_RANDOM_SIZE);

  ssl->hit = 0;
  if (!ssl_get_new_session(ssl, 1 /* server */)) {
    goto err;
  }

  if (ssl->ctx->dos_protection_cb != NULL &&
      ssl->ctx->dos_protection_cb(&early_ctx) == 0) {
    /* Connection rejected for DOS reasons. */
    alert = SSL_AD_ACCESS_DENIED;
    OPENSSL_PUT_ERROR(SSL, SSL_R_CONNECTION_REJECTED);
    goto fatal_err;
  }

  if (!CBS_get_u16_length_prefixed(&cbs, &cipher_suites) ||
      CBS_len(&cipher_suites) == 0 ||
      CBS_len(&cipher_suites) % 2 != 0 ||
      !CBS_get_u8_length_prefixed(&cbs, &compression_methods) ||
      CBS_len(&compression_methods) == 0) {
    alert = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    goto fatal_err;
  }

  ciphers = ssl_bytes_to_cipher_list(ssl, &cipher_suites, max_version);
  if (ciphers == NULL) {
    goto err;
  }

  /* Only null compression is supported. */
  if (memchr(CBS_data(&compression_methods), 0,
             CBS_len(&compression_methods)) == NULL) {
    alert = SSL_AD_ILLEGAL_PARAMETER;
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_COMPRESSION_SPECIFIED);
    goto fatal_err;
  }

  /* TLS extensions. */
  if (!ssl_parse_clienthello_tlsext(ssl, &cbs)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
    goto err;
  }

  if (ciphers == NULL) {
    alert = SSL_AD_ILLEGAL_PARAMETER;
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_CIPHERS_PASSED);
    goto fatal_err;
  }

  /* Let cert callback update server certificates if required */
  if (ssl->cert->cert_cb) {
    int rv = ssl->cert->cert_cb(ssl, ssl->cert->cert_cb_arg);
    if (rv == 0) {
      alert = SSL_AD_INTERNAL_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_CERT_CB_ERROR);
      goto fatal_err;
    }
    if (rv < 0) {
      ssl->rwstate = SSL_X509_LOOKUP;
      ssl->s3->hs->handshake_interrupt = HS_NEED_CB;
      goto err;
    }
  }
  const SSL_CIPHER *cipher = ssl3_choose_cipher(ssl, ciphers,
                                                ssl_get_cipher_preferences(ssl));
  /* unknown cipher */
  if (cipher == NULL) {
    alert = SSL_AD_HANDSHAKE_FAILURE;
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_SHARED_CIPHER);
    goto fatal_err;
  }

  ssl->session->cipher = cipher;
  ssl->s3->hs->cipher = cipher;
  ssl->s3->tmp.new_cipher = cipher;

  const EVP_MD *digest = ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl));
  ssl->s3->hs->key_len = EVP_MD_size(digest);

  ssl->s3->hs->resumption_ctx_len = ssl->s3->hs->key_len;
  ssl->s3->hs->resumption_ctx = OPENSSL_malloc(ssl->s3->hs->key_len);
  memset(ssl->s3->hs->resumption_ctx, 0, ssl->s3->hs->resumption_ctx_len);

  /* Determine whether to request a client certificate. */
  ssl->s3->tmp.cert_request = !!(ssl->verify_mode & SSL_VERIFY_PEER);
  /* CertificateRequest may only be sent in certificate-based ciphers. */
  if (!ssl_cipher_uses_certificate_auth(ssl->s3->tmp.new_cipher)) {
    ssl->s3->tmp.cert_request = 0;
  }

  const uint8_t *key_share_buf = NULL;
  size_t key_share_len = 0;
  CBS key_share;

  if (SSL_early_callback_ctx_extension_get(&early_ctx, TLSEXT_TYPE_key_share,
                                           &key_share_buf, &key_share_len)) {
    CBS_init(&key_share, key_share_buf, key_share_len);
    uint8_t out_alert;
    if (!ext_key_share_parse_clienthello(ssl, &out_alert, &key_share)) {
      alert = out_alert;
      OPENSSL_PUT_ERROR(SSL, SSL_R_ERROR_PARSING_EXTENSION);
      goto fatal_err;
    }
  }

  if (!tls13_derive_secrets(ssl)) {
    goto err;
  }

  if (!ssl3_init_handshake_hash(ssl)) {
    goto err;
  }
  ssl3_free_handshake_buffer(ssl);

  /* There should be nothing left over in the record. */
  if (CBS_len(&cbs) != 0) {
    /* wrong packet length */
    alert = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_PACKET_LENGTH);
    goto fatal_err;
  }

  return 1;

fatal_err:
  ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
err:
  return 0;
}

static int tls13_send_server_hello(SSL *ssl) {
  CBB outer, cbb, extensions;
  if (!ssl->method->init_message(ssl, &outer, &cbb, SSL3_MT_SERVER_HELLO) ||
      !CBB_add_u16(&cbb, ssl->version) ||
      !RAND_bytes(ssl->s3->server_random, sizeof(ssl->s3->server_random)) ||
      !CBB_add_bytes(&cbb, ssl->s3->server_random, SSL3_RANDOM_SIZE) ||
      !CBB_add_u16(&cbb, ssl_cipher_get_value(ssl->s3->hs->cipher)) ||
      !CBB_add_u16_length_prefixed(&cbb, &extensions) ||
      !ext_key_share_add_serverhello(ssl, &extensions) ||
      !ssl->method->finish_message(ssl, &outer)) {
    CBB_cleanup(&outer);
    return 0;
  }

  return 1;
}

static int tls13_send_encrypted_extensions(SSL *ssl) {
  if (!tls13_store_handshake_context(ssl) ||
      !tls13_update_traffic_secret(ssl, type_handshake)) {
    return 0;
  }

  CBB outer, cbb;
  if (!ssl->method->init_message(ssl, &outer, &cbb, SSL3_MT_ENCRYPTED_EXTENSIONS) ||
      !ssl_add_serverhello_tlsext(ssl, &cbb) ||
      !ssl->method->finish_message(ssl, &outer)) {
    CBB_cleanup(&outer);
    return 0;
  }

  return 1;
}

static int tls13_send_certificate_request(SSL *ssl) {
  /* TODO(svaldez): Implement Certificate Request. */

  CBB outer, cbb;
  if (!ssl->method->init_message(ssl, &outer, &cbb, SSL3_MT_CERTIFICATE_REQUEST) ||
      !ssl->method->finish_message(ssl, &outer)) {
    CBB_cleanup(&outer);
    return 0;
  }

  return 1;
}

int tls13_server_handshake(SSL *ssl, SSL_HANDSHAKE *hs) {
  ERR_clear_system_error();
  assert(ssl->server);

  hs->handshake_interrupt = HS_NEED_ERROR;

  switch (hs->handshake_state) {
    case HS_STATE_CLIENT_HELLO:
      if (hs->in_message->type != SSL3_MT_CLIENT_HELLO) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_client_hello(ssl, *hs->in_message)) {
        hs->handshake_state = HS_STATE_SERVER_HELLO;
        hs->handshake_interrupt = HS_NEED_NONE;
      }
      break;
    case HS_STATE_SERVER_HELLO:
      if (tls13_send_server_hello(ssl)) {
        hs->handshake_state = HS_STATE_SERVER_ENCRYPTED_EXTENSIONS;
        hs->handshake_interrupt = HS_NEED_WRITE;
      }
      break;
    case HS_STATE_SERVER_ENCRYPTED_EXTENSIONS:
      if (tls13_send_encrypted_extensions(ssl)) {
        hs->handshake_interrupt = HS_NEED_WRITE;
        if (hs->cipher->algorithm_auth & SSL_aPSK) {
          hs->handshake_state = HS_STATE_SERVER_FINISHED;
          hs->handshake_interrupt |= HS_NEED_FLUSH;
        } else if (ssl->verify_mode & SSL_VERIFY_PEER) {
          hs->handshake_state = HS_STATE_SERVER_CERTIFICATE_REQUEST;
        } else {
          hs->handshake_state = HS_STATE_SERVER_CERTIFICATE;
        }
      }
      break;
    case HS_STATE_SERVER_CERTIFICATE_REQUEST:
      if (tls13_send_certificate_request(ssl)) {
        hs->handshake_state = HS_STATE_SERVER_CERTIFICATE;
        hs->handshake_interrupt = HS_NEED_WRITE;
      }
      break;
    case HS_STATE_SERVER_CERTIFICATE:
      if (tls13_send_certificate(ssl)) {
        hs->handshake_state = HS_STATE_SERVER_CERTIFICATE_VERIFY;
        hs->handshake_interrupt = HS_NEED_WRITE;
      }
      break;
    case HS_STATE_SERVER_CERTIFICATE_VERIFY:
      if (tls13_send_certificate_verify(ssl)) {
        hs->handshake_state = HS_STATE_SERVER_FINISHED;
        hs->handshake_interrupt = HS_NEED_WRITE;
      }
      break;
    case HS_STATE_SERVER_FINISHED:
      if (tls13_send_finished(ssl)) {
        if (!hs->cert_context) {
          if (!tls13_store_handshake_context(ssl)) {
            return 0;
          }
          hs->handshake_state = HS_STATE_CLIENT_FINISHED;
        } else {
          hs->handshake_state = HS_STATE_CLIENT_CERTIFICATE;
        }
        hs->handshake_interrupt = HS_NEED_WRITE_FLIGHT | HS_NEED_READ;
      }
      break;
    case HS_STATE_CLIENT_CERTIFICATE:
      if (!tls13_derive_traffic_secret_0(ssl)) {
        return 0;
      }
      if (hs->in_message->type != SSL3_MT_CERTIFICATE) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_certificate(ssl, *hs->in_message)) {
        hs->handshake_state = HS_STATE_CLIENT_CERTIFICATE_VERIFY;
        hs->handshake_interrupt = HS_NEED_READ;
      }
      break;
    case HS_STATE_CLIENT_CERTIFICATE_VERIFY:
      if (hs->in_message->type != SSL3_MT_CERTIFICATE_VERIFY) {
        return 0;
      }
      if (tls13_receive_certificate_verify(ssl, *hs->in_message)) {
        if (!tls13_store_handshake_context(ssl)) {
          return 0;
        }
        hs->handshake_state = HS_STATE_CLIENT_FINISHED;
        hs->handshake_interrupt = HS_NEED_READ;
      }
      break;
    case HS_STATE_CLIENT_FINISHED:
      if (!hs->cert_context) {
        if (!tls13_derive_traffic_secret_0(ssl)) {
          return 0;
        }
      }
      if (tls13_receive_finished(ssl, *hs->in_message)) {
        hs->handshake_state = HS_STATE_FINISH;
        hs->handshake_interrupt = HS_NEED_NONE;
      }
      break;
    case HS_STATE_FINISH:
      if (!tls13_finalize_keys(ssl)) {
        return 0;
      }
      hs->handshake_state = HS_STATE_DONE;
      hs->handshake_interrupt = HS_NEED_NONE;
      break;
    default:
      return 0;
  }

  return hs->handshake_interrupt != HS_NEED_ERROR;
}
