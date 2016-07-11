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

#include <openssl/bn.h>
#include <openssl/buf.h>
#include <openssl/bytestring.h>
#include <openssl/dh.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/mem.h>
#include <openssl/rand.h>

#include "internal.h"
#include "../crypto/dh/internal.h"

static int tls13_receive_server_hello(SSL *ssl) {
  int alert;

  CBS cbs;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);

  CBS server_random;
  uint16_t server_wire_version;
  uint16_t cipher_suite;
  if (!CBS_get_u16(&cbs, &server_wire_version) ||
      !CBS_get_bytes(&cbs, &server_random, SSL3_RANDOM_SIZE) ||
      !CBS_get_u16(&cbs, &cipher_suite)) {
    alert = SSL_AD_DECODE_ERROR;
    goto fatal_err;
  }

  assert(ssl->s3->have_version);
  memcpy(ssl->s3->server_random, CBS_data(&server_random), SSL3_RANDOM_SIZE);

  ssl->hit = 0;
  if (!ssl_get_new_session(ssl, 0)) {
    alert = SSL_AD_INTERNAL_ERROR;
    goto fatal_err;
  }

  CERT *ct = ssl->cert;
  const SSL_CIPHER *cipher = SSL_get_cipher_by_value(cipher_suite);
  /* unknown cipher */
  if (cipher == NULL) {
    alert = SSL_AD_ILLEGAL_PARAMETER;
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNKNOWN_CIPHER_RETURNED);
    goto fatal_err;
  }
  /* disabled cipher */
  if ((cipher->algorithm_mkey & ct->mask_k) ||
      (cipher->algorithm_auth & ct->mask_a) ||
      SSL_CIPHER_get_min_version(cipher) > ssl3_protocol_version(ssl) ||
      SSL_CIPHER_get_max_version(cipher) < ssl3_protocol_version(ssl) ||
      !sk_SSL_CIPHER_find(ssl_get_ciphers_by_id(ssl), NULL, cipher)) {
    alert = SSL_AD_ILLEGAL_PARAMETER;
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_CIPHER_RETURNED);
    goto fatal_err;
  }

  ssl->session->cipher = cipher;
  ssl->s3->hs->cipher = cipher;
  ssl->s3->tmp.new_cipher = cipher;

  const EVP_MD *digest = ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl));
  ssl->s3->hs->key_len = EVP_MD_size(digest);

  ssl->s3->hs->resumption_ctx_len = ssl->s3->hs->key_len;
  memset(ssl->s3->hs->resumption_ctx, 0, ssl->s3->hs->resumption_ctx_len);

  if (!ssl3_init_handshake_hash(ssl)) {
    goto err;
  }
  ssl3_free_handshake_buffer(ssl);

  /* TLS extensions */
  if (CBS_len(&cbs) != 0) {
    /* Decode the extensions block and check it is valid. */
    CBS extensions;
    if (!CBS_get_u16_length_prefixed(&cbs, &extensions)) {
      alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
      goto err;
    }

    while (CBS_len(&extensions) != 0) {
      uint16_t type;
      CBS extension;

      /* Decode the next extension. */
      if (!CBS_get_u16(&extensions, &type) ||
          !CBS_get_u16_length_prefixed(&extensions, &extension)) {
        alert = SSL_AD_DECODE_ERROR;
        OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
        goto err;
      }

      int valid = 0;
      uint8_t ext_alert = SSL_AD_DECODE_ERROR;
      if (type == TLSEXT_TYPE_key_share) {
        valid = ext_key_share_parse_serverhello(ssl, &ext_alert, &extension);
      } else {
        /* If the extension was never sent then it is illegal. */
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_EXTENSION);
        ERR_add_error_dataf("extension :%u", (unsigned)type);
        alert = SSL_AD_DECODE_ERROR;
        OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
        goto err;
      }

      if (!valid) {
        OPENSSL_PUT_ERROR(SSL, SSL_R_ERROR_PARSING_EXTENSION);
        ERR_add_error_dataf("extension: %u", (unsigned)type);
        alert = ext_alert;
        goto err;
      }
    }
  }

  if (!tls13_derive_secrets(ssl) ||
      !tls13_store_handshake_context(ssl) ||
      !tls13_update_traffic_secret(ssl, type_handshake)) {
    goto err;
  }

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

static int tls13_receive_encrypted_extensions(SSL *ssl) {
  int alert = 0;

  CBS cbs;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);

  /* TLS extensions */
  if (!ssl_parse_serverhello_tlsext(ssl, &cbs)) {
    alert = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
    goto err;
  }

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

static int tls13_receive_certificate_request(SSL *ssl) {
  ssl->s3->tmp.cert_request = 0;

  CBS cbs;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);

  CBS context, supported_signature_algorithms;
  if (!CBS_get_u8_length_prefixed(&cbs, &context) ||
      !CBS_stow(&context, &ssl->s3->hs->cert_context, &ssl->s3->hs->cert_context_len) ||
      !CBS_get_u16_length_prefixed(&cbs, &supported_signature_algorithms) ||
      !tls1_parse_peer_sigalgs(ssl, &supported_signature_algorithms)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    return 0;
  }

  uint8_t alert;
  STACK_OF(X509_NAME) *ca_sk = ssl_parse_client_CA_list(ssl, &alert, &cbs);
  if (ca_sk == NULL) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
    return 0;
  }

  // TODO(svaldez): certificate_extensions

  ssl->s3->tmp.cert_request = 1;
  sk_X509_NAME_pop_free(ssl->s3->tmp.ca_names, X509_NAME_free);
  ssl->s3->tmp.ca_names = ca_sk;
  return 1;
}


int tls13_client_handshake(SSL *ssl, SSL_HANDSHAKE *hs) {
  ERR_clear_system_error();
  assert(!ssl->server);

  hs->handshake_interrupt |= HS_NEED_ERROR;

  switch (hs->handshake_state) {
    case HS_STATE_CLIENT_HELLO:
      /* TODO(svaldez): Implement 0RTT. */
      assert(0);
      break;
    case HS_STATE_CLIENT_ENCRYPTED_EXTENSIONS:
      /* TODO(svaldez): Deal with Client Encrypted Extensions */
      hs->handshake_state = HS_STATE_CLIENT_EARLY_FINISHED;
      hs->handshake_interrupt = HS_NEED_WRITE;
      break;
    case HS_STATE_CLIENT_EARLY_FINISHED:
      if (tls13_send_finished(ssl)) {
        hs->handshake_state = HS_STATE_SERVER_HELLO;
        hs->handshake_interrupt = HS_NEED_WRITE_FLIGHT | HS_NEED_READ;
      }
      break;
    case HS_STATE_SERVER_HELLO:
      if (ssl->s3->tmp.message_type == SSL3_MT_HELLO_RETRY_REQUEST) {
        /* TODO(svaldez): Handle HelloRetryRequest (might kill 0-RTT) */
      }
      if (ssl->s3->tmp.message_type != SSL3_MT_SERVER_HELLO) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_server_hello(ssl)) {
        hs->handshake_state = HS_STATE_SERVER_ENCRYPTED_EXTENSIONS;
        hs->handshake_interrupt = HS_NEED_READ;
      }
      break;
    case HS_STATE_SERVER_ENCRYPTED_EXTENSIONS:
      if (ssl->s3->tmp.message_type != SSL3_MT_ENCRYPTED_EXTENSIONS) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_encrypted_extensions(ssl)) {
        if (hs->cipher->algorithm_auth & SSL_aPSK) {
          if (!tls13_store_handshake_context(ssl)) {
            return 0;
          }
          hs->handshake_state = HS_STATE_SERVER_FINISHED;
        } else {
          hs->handshake_state = HS_STATE_SERVER_CERTIFICATE_REQUEST;
        }
        hs->handshake_interrupt = HS_NEED_READ;
      }
      break;
    case HS_STATE_SERVER_CERTIFICATE_REQUEST:
      if (ssl->s3->tmp.message_type == SSL3_MT_CERTIFICATE_REQUEST) {
        if (tls13_receive_certificate_request(ssl)) {
          hs->handshake_state = HS_STATE_SERVER_CERTIFICATE;
          hs->handshake_interrupt = HS_NEED_READ;
        }
      } else {
        hs->handshake_state = HS_STATE_SERVER_CERTIFICATE;
        hs->handshake_interrupt = HS_NEED_NONE;
      }
      break;
    case HS_STATE_SERVER_CERTIFICATE:
      if (ssl->s3->tmp.message_type != SSL3_MT_CERTIFICATE) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_certificate(ssl)) {
        hs->handshake_state = HS_STATE_SERVER_CERTIFICATE_VERIFY;
        hs->handshake_interrupt = HS_NEED_READ;
      }
      break;
    case HS_STATE_SERVER_CERTIFICATE_VERIFY:
      if (ssl->s3->tmp.message_type != SSL3_MT_CERTIFICATE_VERIFY) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_certificate_verify(ssl)) {
        if (!tls13_store_handshake_context(ssl)) {
          return 0;
        }
        hs->handshake_state = HS_STATE_SERVER_FINISHED;
        hs->handshake_interrupt = HS_NEED_READ;
      }
      break;
    case HS_STATE_SERVER_FINISHED:
      if (ssl->s3->tmp.message_type != SSL3_MT_FINISHED) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_finished(ssl)) {
        if (!tls13_store_handshake_context(ssl) ||
            !tls13_derive_traffic_secret_0(ssl)) {
          return 0;
        }
        if (ssl->s3->tmp.cert_request) {
          hs->handshake_state = HS_STATE_CLIENT_CERTIFICATE;
        } else {
          hs->handshake_state = HS_STATE_CLIENT_FINISHED;
        }
        hs->handshake_interrupt = HS_NEED_NONE;
      }
      break;
    case HS_STATE_CLIENT_CERTIFICATE:
      if (tls13_send_certificate(ssl)) {
        /* TODO(davidben): These should all be switched to a "skip"-like pattern
         * to keep it all linear. */
        hs->handshake_state = ssl_has_certificate(ssl)
                                  ? HS_STATE_CLIENT_CERTIFICATE_VERIFY
                                  : HS_STATE_CLIENT_FINISHED;
        hs->handshake_interrupt = HS_NEED_WRITE;
      }
      break;
    case HS_STATE_CLIENT_CERTIFICATE_VERIFY:
      if (tls13_send_certificate_verify(ssl)) {
        hs->handshake_state = HS_STATE_CLIENT_FINISHED;
        hs->handshake_interrupt = HS_NEED_WRITE;
      }
      break;
    case HS_STATE_CLIENT_FINISHED:
      if (tls13_send_finished(ssl)) {
        hs->handshake_state = HS_STATE_FINISH;
        hs->handshake_interrupt = HS_NEED_WRITE_FLIGHT;
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

  return !(hs->handshake_interrupt & HS_NEED_ERROR);
}
