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

#include <openssl/bytestring.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/stack.h>
#include <openssl/x509.h>

#include "internal.h"


static int tls13_receive_hello_retry_request(SSL *ssl) {
  CBS cbs;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);

  CBS extensions;
  uint16_t server_wire_version, cipher_suite, group_id;
  if (!CBS_get_u16(&cbs, &server_wire_version) ||
      !CBS_get_u16(&cbs, &cipher_suite) ||
      !CBS_get_u16(&cbs, &group_id) ||
      !CBS_get_u16_length_prefixed(&cbs, &extensions) ||
      CBS_len(&cbs) != 0) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return 0;
  }

  /* TODO(svaldez): Add HelloRetryRequest extension handling. */
  /* TODO(svaldez): Remove 0RTT. */

  const uint16_t *groups;
  size_t groups_len;
  tls1_get_grouplist(ssl, 0 /* local groups */, &groups, &groups_len);
  int found = 0;
  for (size_t i = 0; i < groups_len; i++) {
    if (groups[i] == group_id) {
      found = 1;
      break;
    }
  }

  if (!found) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
    return 0;
  }

  for (size_t i = 0; i < ssl->s3->hs->groups_len; i++) {
    /* TODO(svaldez): Don't enforce this check when HRR is due to Cookie. */
    if (SSL_ECDH_CTX_get_id(&ssl->s3->hs->groups[i]) == group_id) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
      return 0;
    }
    SSL_ECDH_CTX_cleanup(&ssl->s3->hs->groups[i]);
  }

  OPENSSL_free(ssl->s3->hs->groups);
  ssl->s3->hs->groups = NULL;
  ssl->s3->hs->hrr_group = group_id;

  return 1;
}

static int tls13_send_hrr_client_hello(SSL *ssl) {
  CBB cbb;
  CBB_zero(&cbb);

  uint16_t min_version, max_version;
  if (!ssl_get_version_range(ssl, &min_version, &max_version)) {
    goto err;
  }

  int has_session = ssl->session != NULL &&
                    !ssl->s3->initial_handshake_complete;

  CBB body, child;
  if (!ssl->method->init_message(ssl, &cbb, &body, SSL3_MT_CLIENT_HELLO) ||
      !CBB_add_u16(&body, ssl->client_version) ||
      !CBB_add_bytes(&body, ssl->s3->client_random, SSL3_RANDOM_SIZE) ||
      !CBB_add_u8_length_prefixed(&body, &child) ||
      (has_session &&
       !CBB_add_bytes(&child, ssl->session->session_id,
                      ssl->session->session_id_length))) {
    goto err;
  }

  if (SSL_IS_DTLS(ssl)) {
    if (!CBB_add_u8_length_prefixed(&body, &child) ||
        !CBB_add_bytes(&child, ssl->d1->cookie, ssl->d1->cookie_len)) {
      goto err;
    }
  }

  size_t header_len =
      SSL_IS_DTLS(ssl) ? DTLS1_HM_HEADER_LENGTH : SSL3_HM_HEADER_LENGTH;
  if (!ssl3_write_client_cipher_list(ssl, &body, min_version, max_version) ||
      !CBB_add_u8(&body, 1 /* one compression method */) ||
      !CBB_add_u8(&body, 0 /* null compression */) ||
      !ssl_add_clienthello_tlsext(ssl, &body, header_len + CBB_len(&body)) ||
      !ssl->method->finish_message(ssl, &cbb)) {
    goto err;
  }

  return 1;

err:
  CBB_cleanup(&cbb);
  return 0;
}

static int tls13_receive_server_hello(SSL *ssl) {
  CBS cbs, server_random, extensions;
  uint16_t server_wire_version;
  uint16_t cipher_suite;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);
  if (!CBS_get_u16(&cbs, &server_wire_version) ||
      !CBS_get_bytes(&cbs, &server_random, SSL3_RANDOM_SIZE) ||
      !CBS_get_u16(&cbs, &cipher_suite) ||
      !CBS_get_u16_length_prefixed(&cbs, &extensions) ||
      CBS_len(&cbs) != 0) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return 0;
  }

  /* Parse out the extensions. */
  int have_key_share = 0;
  CBS key_share;
  while (CBS_len(&extensions) != 0) {
    uint16_t type;
    CBS extension;
    if (!CBS_get_u16(&extensions, &type) ||
        !CBS_get_u16_length_prefixed(&extensions, &extension)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
      return 0;
    }

    switch (type) {
      case TLSEXT_TYPE_key_share:
        if (have_key_share) {
          OPENSSL_PUT_ERROR(SSL, SSL_R_DUPLICATE_EXTENSION);
          ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
          return 0;
        }
        key_share = extension;
        have_key_share = 1;
        break;
      default:
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_EXTENSION);
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNSUPPORTED_EXTENSION);
        return 0;
    }
  }

  assert(ssl->s3->have_version);
  memcpy(ssl->s3->server_random, CBS_data(&server_random), SSL3_RANDOM_SIZE);

  ssl->hit = 0;
  if (!ssl_get_new_session(ssl, 0)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
    return 0;
  }

  const SSL_CIPHER *cipher = SSL_get_cipher_by_value(cipher_suite);
  /* unknown cipher */
  if (cipher == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNKNOWN_CIPHER_RETURNED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
    return 0;
  }
  /* disabled cipher */
  if ((cipher->algorithm_mkey & ssl->cert->mask_k) ||
      (cipher->algorithm_auth & ssl->cert->mask_a) ||
      SSL_CIPHER_get_min_version(cipher) > ssl3_protocol_version(ssl) ||
      SSL_CIPHER_get_max_version(cipher) < ssl3_protocol_version(ssl) ||
      !sk_SSL_CIPHER_find(ssl_get_ciphers_by_id(ssl), NULL, cipher)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_CIPHER_RETURNED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
    return 0;
  }

  ssl->session->cipher = cipher;
  ssl->s3->tmp.new_cipher = cipher;

  /* The PRF hash is now known. Set up the key schedule. */
  static const uint8_t kZeroes[EVP_MAX_MD_SIZE] = {0};
  size_t hash_len =
      EVP_MD_size(ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl)));
  if (!tls13_init_key_schedule(ssl, kZeroes, hash_len)) {
    return 0;
  }

  /* Resolve PSK and incorporate it into the secret. */
  if (cipher->algorithm_auth == SSL_aPSK) {
    /* TODO(davidben): Support PSK. */
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return 0;
  } else if (!tls13_advance_key_schedule(ssl, kZeroes, hash_len)) {
    return 0;
  }

  /* Resolve ECDHE and incorporate it into the secret. */
  if (cipher->algorithm_mkey == SSL_kECDHE) {
    if (!have_key_share) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_MISSING_KEY_SHARE);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_MISSING_EXTENSION);
      return 0;
    }

    uint8_t *dhe_secret;
    size_t dhe_secret_len;
    uint8_t alert = SSL_AD_DECODE_ERROR;
    if (!ext_key_share_parse_serverhello(ssl, &dhe_secret, &dhe_secret_len,
                                         &alert, &key_share)) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
      return 0;
    }

    int ok = tls13_advance_key_schedule(ssl, dhe_secret, dhe_secret_len);
    OPENSSL_free(dhe_secret);
    if (!ok) {
      return 0;
    }
  } else {
    if (have_key_share) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_EXTENSION);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNSUPPORTED_EXTENSION);
      return 0;
    }
    if (!tls13_advance_key_schedule(ssl, kZeroes, hash_len)) {
      return 0;
    }
    return 0;
  }

  if (!tls13_set_handshake_traffic(ssl)) {
    return 0;
  }

  return 1;
}

static int tls13_receive_encrypted_extensions(SSL *ssl) {
  CBS cbs;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);
  if (!ssl_parse_serverhello_tlsext(ssl, &cbs)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
    return 0;
  }
  if (CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return 0;
  }

  return 1;
}

static int tls13_receive_certificate_request(SSL *ssl) {
  ssl->s3->tmp.cert_request = 0;

  CBS cbs, context, supported_signature_algorithms;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);
  if (!CBS_get_u8_length_prefixed(&cbs, &context) ||
      !CBS_stow(&context, &ssl->s3->hs->cert_context,
                &ssl->s3->hs->cert_context_len) ||
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

  /* Ignore extensions. */
  CBS extensions;
  if (!CBS_get_u16_length_prefixed(&cbs, &extensions) ||
      CBS_len(&cbs) != 0) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    return 0;
  }

  ssl->s3->tmp.cert_request = 1;
  sk_X509_NAME_pop_free(ssl->s3->tmp.ca_names, X509_NAME_free);
  ssl->s3->tmp.ca_names = ca_sk;
  return 1;
}


int tls13_client_handshake(SSL *ssl, SSL_HANDSHAKE *hs) {
  assert(!ssl->server);

  if (hs->interrupt == hs_interrupt_none) {
    hs->interrupt = hs_interrupt_error;
  }

  switch (hs->state) {
    case HS_STATE_CLIENT_HELLO:
      /* TODO(svaldez): Implement 0RTT. */
      assert(0);
      break;
    case HS_STATE_HELLO_RETRY_REQUEST:
      if (ssl->s3->tmp.message_type != SSL3_MT_HELLO_RETRY_REQUEST) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_hello_retry_request(ssl)) {
        hs->state = HS_STATE_HRR_CLIENT_HELLO;
        hs->interrupt = hs_interrupt_none;
      }
      break;
    case HS_STATE_HRR_CLIENT_HELLO:
      if (tls13_send_hrr_client_hello(ssl)) {
        hs->state = HS_STATE_HRR_FLUSH;
        hs->interrupt = hs_interrupt_write_flight;
      }
      break;
    case HS_STATE_HRR_FLUSH:
      hs->state = HS_STATE_SERVER_HELLO;
      hs->interrupt = hs_interrupt_read;
    case HS_STATE_SERVER_HELLO:
      if (ssl->s3->tmp.message_type != SSL3_MT_SERVER_HELLO) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_server_hello(ssl)) {
        hs->state = HS_STATE_SERVER_ENCRYPTED_EXTENSIONS;
        hs->interrupt = hs_interrupt_read;
      }
      break;
    case HS_STATE_SERVER_ENCRYPTED_EXTENSIONS:
      if (ssl->s3->tmp.message_type != SSL3_MT_ENCRYPTED_EXTENSIONS) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_encrypted_extensions(ssl)) {
        if (!ssl->method->hash_current_message(ssl)) {
          return 0;
        }
        if (ssl->s3->tmp.new_cipher->algorithm_auth & SSL_aPSK) {
          hs->state = HS_STATE_SERVER_FINISHED;
          hs->interrupt = hs_interrupt_read;
        } else {
          hs->state = HS_STATE_SERVER_CERTIFICATE_REQUEST;
          hs->interrupt = hs_interrupt_read;
        }
      }
      break;
    case HS_STATE_SERVER_CERTIFICATE_REQUEST:
      if (ssl->s3->tmp.message_type == SSL3_MT_CERTIFICATE_REQUEST) {
        if (tls13_receive_certificate_request(ssl)) {
          if (!ssl->method->hash_current_message(ssl)) {
            return 0;
          }
          hs->state = HS_STATE_SERVER_CERTIFICATE;
          hs->interrupt = hs_interrupt_read;
        }
      } else {
        hs->state = HS_STATE_SERVER_CERTIFICATE;
        hs->interrupt = hs_interrupt_none;
      }
      break;
    case HS_STATE_SERVER_CERTIFICATE:
      if (ssl->s3->tmp.message_type != SSL3_MT_CERTIFICATE) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_certificate(ssl)) {
        if (!ssl->method->hash_current_message(ssl)) {
          return 0;
        }
        hs->state = HS_STATE_SERVER_CERTIFICATE_VERIFY;
        hs->interrupt = hs_interrupt_read;
      }
      break;
    case HS_STATE_SERVER_CERTIFICATE_VERIFY:
      if (ssl->s3->tmp.message_type != SSL3_MT_CERTIFICATE_VERIFY) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_certificate_verify(ssl)) {
        if (!ssl->method->hash_current_message(ssl)) {
          return 0;
        }
        hs->state = HS_STATE_SERVER_FINISHED;
        hs->interrupt = hs_interrupt_read;
      }
      break;
    case HS_STATE_SERVER_FINISHED:
      if (ssl->s3->tmp.message_type != SSL3_MT_FINISHED) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_finished(ssl)) {
        if (!ssl->method->hash_current_message(ssl)) {
          return 0;
        }
        /* Update the secret to the master secret and derive traffic keys. */
        static const uint8_t kZeroes[EVP_MAX_MD_SIZE] = {0};
        size_t hash_len =
            EVP_MD_size(ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl)));
        if (!tls13_advance_key_schedule(ssl, kZeroes, hash_len) ||
            !tls13_derive_traffic_secret_0(ssl)) {
          return 0;
        }

        hs->state = HS_STATE_SERVER_FLUSH;
        hs->interrupt = hs_interrupt_none;
      }
      break;
    case HS_STATE_SERVER_FLUSH:
      if (ssl->s3->tmp.cert_request) {
        hs->state = HS_STATE_CLIENT_CERTIFICATE;
      } else {
        hs->state = HS_STATE_CLIENT_FINISHED;
      }
      hs->interrupt = hs_interrupt_none;
      break;
    case HS_STATE_CLIENT_CERTIFICATE:
      if (tls13_send_certificate(ssl)) {
        /* TODO(davidben): These should all be switched to a "skip"-like pattern
         * to keep it all linear. */
        hs->state = ssl_has_certificate(ssl)
                                  ? HS_STATE_CLIENT_CERTIFICATE_VERIFY
                                  : HS_STATE_CLIENT_FINISHED;
        hs->interrupt = hs_interrupt_write;
      }
      break;
    case HS_STATE_CLIENT_CERTIFICATE_VERIFY:
      if (tls13_send_certificate_verify(ssl)) {
        hs->state = HS_STATE_CLIENT_FINISHED;
        hs->interrupt = hs_interrupt_write;
      }
      break;
    case HS_STATE_CLIENT_FINISHED:
      if (tls13_send_finished(ssl)) {
        hs->state = HS_STATE_FINISH;
        hs->interrupt = hs_interrupt_write_flight;
      }
      break;
    case HS_STATE_FINISH:
      if (!tls13_set_traffic_key(ssl, type_data, evp_aead_open,
                                 hs->traffic_secret_0, hs->hash_len) ||
          !tls13_set_traffic_key(ssl, type_data, evp_aead_seal,
                                 hs->traffic_secret_0, hs->hash_len) ||
          !tls13_finalize_keys(ssl)) {
        return 0;
      }
      hs->state = HS_STATE_DONE;
      hs->interrupt = hs_interrupt_none;
      break;
    default:
      return 0;
  }

  return hs->interrupt != hs_interrupt_error;
}
