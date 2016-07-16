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
#include <openssl/rand.h>
#include <openssl/stack.h>

#include "internal.h"


static int tls13_receive_client_hello(SSL *ssl) {
  struct ssl_early_callback_ctx early_ctx;
  uint16_t client_wire_version;
  CBS client_random, session_id, cipher_suites, compression_methods;

  memset(&early_ctx, 0, sizeof(early_ctx));
  early_ctx.ssl = ssl;
  early_ctx.client_hello = ssl->init_msg;
  early_ctx.client_hello_len = ssl->init_num;
  if (!ssl_early_callback_init(&early_ctx)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_CLIENTHELLO_PARSE_FAILED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return 0;
  }

  CBS cbs;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);

  if (!CBS_get_u16(&cbs, &client_wire_version) ||
      !CBS_get_bytes(&cbs, &client_random, SSL3_RANDOM_SIZE) ||
      !CBS_get_u8_length_prefixed(&cbs, &session_id) ||
      CBS_len(&session_id) > SSL_MAX_SSL_SESSION_ID_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return 0;
  }

  uint16_t min_version, max_version;
  if (!ssl_get_version_range(ssl, &min_version, &max_version)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_PROTOCOL_VERSION);
    return 0;
  }

  assert(ssl->s3->have_version);

  /* Load the client random. */
  memcpy(ssl->s3->client_random, CBS_data(&client_random), SSL3_RANDOM_SIZE);

  ssl->hit = 0;
  if (!ssl_get_new_session(ssl, 1 /* server */)) {
    return 0;
  }

  if (ssl->ctx->dos_protection_cb != NULL &&
      ssl->ctx->dos_protection_cb(&early_ctx) == 0) {
    /* Connection rejected for DOS reasons. */
    OPENSSL_PUT_ERROR(SSL, SSL_R_CONNECTION_REJECTED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ACCESS_DENIED);
    return 0;
  }

  if (!CBS_get_u16_length_prefixed(&cbs, &cipher_suites) ||
      CBS_len(&cipher_suites) == 0 ||
      CBS_len(&cipher_suites) % 2 != 0 ||
      !CBS_get_u8_length_prefixed(&cbs, &compression_methods) ||
      CBS_len(&compression_methods) == 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return 0;
  }

  int ret = 0;
  STACK_OF(SSL_CIPHER) *ciphers =
      ssl_bytes_to_cipher_list(ssl, &cipher_suites, max_version);
  if (ciphers == NULL) {
    goto err;
  }

  /* TLS 1.3 requires the peer only advertise the null compression. */
  if (CBS_len(&compression_methods) != 1 ||
      CBS_data(&compression_methods)[0] != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_INVALID_COMPRESSION_LIST);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
    goto err;
  }

  /* TLS extensions. */
  if (!ssl_parse_clienthello_tlsext(ssl, &cbs)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
    goto err;
  }

  /* There should be nothing left over in the message. */
  if (CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_PACKET_LENGTH);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    goto err;
  }

  if (ciphers == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_CIPHERS_PASSED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
    goto err;
  }

  /* Let cert callback update server certificates if required */
  if (ssl->cert->cert_cb) {
    int rv = ssl->cert->cert_cb(ssl, ssl->cert->cert_cb_arg);
    if (rv == 0) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_CERT_CB_ERROR);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
      goto err;
    } else if (rv < 0) {
      ssl->rwstate = SSL_X509_LOOKUP;
      ssl->s3->hs->interrupt = hs_interrupt_cb;
      goto err;
    } else {
      ssl->s3->hs->interrupt = hs_interrupt_none;
    }
  }
  const SSL_CIPHER *cipher = ssl3_choose_cipher(ssl, ciphers,
                                                ssl_get_cipher_preferences(ssl));
  /* unknown cipher */
  if (cipher == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_SHARED_CIPHER);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
    goto err;
  }

  ssl->session->cipher = cipher;
  ssl->s3->tmp.new_cipher = cipher;

  /* The PRF hash is now known. Set up the key schedule. */
  static const uint8_t kZeroes[EVP_MAX_MD_SIZE] = {0};
  size_t hash_len =
      EVP_MD_size(ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl)));
  if (!tls13_init_key_schedule(ssl, kZeroes, hash_len)) {
    goto err;
  }

  /* Determine whether to request a client certificate. */
  ssl->s3->tmp.cert_request = !!(ssl->verify_mode & SSL_VERIFY_PEER);
  /* CertificateRequest may only be sent in certificate-based ciphers. */
  if (!ssl_cipher_uses_certificate_auth(ssl->s3->tmp.new_cipher)) {
    ssl->s3->tmp.cert_request = 0;
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
    const uint8_t *key_share_buf = NULL;
    size_t key_share_len = 0;
    CBS key_share;
    if (!SSL_early_callback_ctx_extension_get(&early_ctx, TLSEXT_TYPE_key_share,
                                              &key_share_buf, &key_share_len)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_MISSING_KEY_SHARE);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_MISSING_EXTENSION);
      return 0;
    }

    CBS_init(&key_share, key_share_buf, key_share_len);
    int found_dhe;
    uint8_t *dhe_secret;
    size_t dhe_secret_len;
    uint8_t alert;
    if (!ext_key_share_parse_clienthello(ssl, &found_dhe, &dhe_secret, &dhe_secret_len,
                                         &alert, &key_share)) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
      goto err;
    }

    if (found_dhe) {
      int ok = tls13_advance_key_schedule(ssl, dhe_secret, dhe_secret_len);
      OPENSSL_free(dhe_secret);
      if (!ok) {
        return 0;
      }
    } else {
      /* Couldn't find the KeyShare and must send HelloRetryRequest. */
      ssl->s3->hs->hrr_group = 1;
    }
  } else if (!tls13_advance_key_schedule(ssl, kZeroes, hash_len)) {
    return 0;
  }

  ret = 1;

err:
  sk_SSL_CIPHER_free(ciphers);
  return ret;
}

static int tls13_send_hello_retry_request(SSL *ssl) {
  CBB outer, cbb, extensions;
  uint16_t group_id;
  if (!ssl->method->init_message(ssl, &outer, &cbb,
                                 SSL3_MT_HELLO_RETRY_REQUEST) ||
      !CBB_add_u16(&cbb, ssl->version) ||
      !CBB_add_u16(&cbb, ssl_cipher_get_value(ssl->s3->tmp.new_cipher)) ||
      !tls1_get_shared_group(ssl, &group_id) ||
      !CBB_add_u16(&cbb, group_id) ||
      !CBB_add_u16_length_prefixed(&cbb, &extensions) ||
      !ssl->method->finish_message(ssl, &outer)) {
    CBB_cleanup(&outer);
    return 0;
  }

  return 1;
}

static int tls13_receive_hrr_client_hello(SSL *ssl) {
  struct ssl_early_callback_ctx early_ctx;

  memset(&early_ctx, 0, sizeof(early_ctx));
  early_ctx.ssl = ssl;
  early_ctx.client_hello = ssl->init_msg;
  early_ctx.client_hello_len = ssl->init_num;
  if (!ssl_early_callback_init(&early_ctx)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_CLIENTHELLO_PARSE_FAILED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return 0;
  }

  static const uint8_t kZeroes[EVP_MAX_MD_SIZE] = {0};
  size_t hash_len = EVP_MD_size(ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl)));

  /* Resolve ECDHE and incorporate it into the secret. */
  if (ssl->s3->tmp.new_cipher->algorithm_mkey == SSL_kECDHE) {
    const uint8_t *key_share_buf = NULL;
    size_t key_share_len = 0;
    CBS key_share;
    if (!SSL_early_callback_ctx_extension_get(&early_ctx, TLSEXT_TYPE_key_share,
                                              &key_share_buf, &key_share_len)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_MISSING_KEY_SHARE);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_MISSING_EXTENSION);
      return 0;
    }

    CBS_init(&key_share, key_share_buf, key_share_len);
    int found_dhe;
    uint8_t *dhe_secret;
    size_t dhe_secret_len;
    uint8_t alert;
    if (!ext_key_share_parse_clienthello(ssl, &found_dhe, &dhe_secret, &dhe_secret_len,
                                         &alert, &key_share)) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
      return 0;
    }

    if (found_dhe) {
      int ok = tls13_advance_key_schedule(ssl, dhe_secret, dhe_secret_len);
      OPENSSL_free(dhe_secret);
      if (!ok) {
        return 0;
      }
    } else {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
      return 0;
    }
  } else if (!tls13_advance_key_schedule(ssl, kZeroes, hash_len)) {
    return 0;
  }

  return 1;
}

static int tls13_send_server_hello(SSL *ssl) {
  CBB cbb, body, extensions;
  if (!ssl->method->init_message(ssl, &cbb, &body, SSL3_MT_SERVER_HELLO) ||
      !CBB_add_u16(&body, ssl->version) ||
      !RAND_bytes(ssl->s3->server_random, sizeof(ssl->s3->server_random)) ||
      !CBB_add_bytes(&body, ssl->s3->server_random, SSL3_RANDOM_SIZE) ||
      !CBB_add_u16(&body, ssl_cipher_get_value(ssl->s3->tmp.new_cipher)) ||
      !CBB_add_u16_length_prefixed(&body, &extensions) ||
      !ext_key_share_add_serverhello(ssl, &extensions) ||
      !ssl->method->finish_message(ssl, &cbb)) {
    CBB_cleanup(&cbb);
    return 0;
  }

  return 1;
}

static int tls13_send_encrypted_extensions(SSL *ssl) {
  if (!tls13_set_handshake_traffic(ssl)) {
    return 0;
  }

  CBB cbb, body;
  if (!ssl->method->init_message(ssl, &cbb, &body,
                                 SSL3_MT_ENCRYPTED_EXTENSIONS) ||
      !ssl_add_serverhello_tlsext(ssl, &body) ||
      !ssl->method->finish_message(ssl, &cbb)) {
    CBB_cleanup(&cbb);
    return 0;
  }

  return 1;
}

static int tls13_send_certificate_request(SSL *ssl) {
  CBB cbb, body, sigalgs_cbb;
  if (!ssl->method->init_message(ssl, &cbb, &body,
                                 SSL3_MT_CERTIFICATE_REQUEST) ||
      !CBB_add_u8(&body, 0 /* no certificate_request_context. */)) {
    goto err;
  }

  const uint16_t *sigalgs;
  size_t sigalgs_len = tls12_get_psigalgs(ssl, &sigalgs);
  if (!CBB_add_u16_length_prefixed(&body, &sigalgs_cbb)) {
    goto err;
  }

  for (size_t i = 0; i < sigalgs_len; i++) {
    if (!CBB_add_u16(&sigalgs_cbb, sigalgs[i])) {
      goto err;
    }
  }

  if (!ssl_add_client_CA_list(ssl, &body) ||
      !CBB_add_u16(&body, 0 /* empty certificate_extensions. */) ||
      !ssl->method->finish_message(ssl, &cbb)) {
    goto err;
  }

  return 1;

err:
  CBB_cleanup(&cbb);
  return 0;
}

int tls13_server_handshake(SSL *ssl, SSL_HANDSHAKE *hs) {
  assert(ssl->server);

  if (hs->interrupt == hs_interrupt_none) {
    hs->interrupt = hs_interrupt_error;
  }

  switch (hs->state) {
    case HS_STATE_CLIENT_HELLO:
      if (ssl->s3->tmp.message_type != SSL3_MT_CLIENT_HELLO) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_client_hello(ssl)) {
        if (hs->hrr_group) {
          hs->state = HS_STATE_HELLO_RETRY_REQUEST;
        } else {
          hs->state = HS_STATE_SERVER_HELLO;
        }
        hs->interrupt = hs_interrupt_none;
      }
      break;
    case HS_STATE_HELLO_RETRY_REQUEST:
      if (tls13_send_hello_retry_request(ssl)) {
        hs->state = HS_STATE_HRR_FLUSH;
        hs->interrupt = hs_interrupt_write_flight;
      }
      break;
    case HS_STATE_HRR_FLUSH:
      hs->state = HS_STATE_HRR_CLIENT_HELLO;
      hs->interrupt = hs_interrupt_read;
    case HS_STATE_HRR_CLIENT_HELLO:
      if (ssl->s3->tmp.message_type != SSL3_MT_CLIENT_HELLO) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_hrr_client_hello(ssl)) {
        hs->state = HS_STATE_SERVER_HELLO;
        hs->interrupt = hs_interrupt_none;
      }
      break;
    case HS_STATE_SERVER_HELLO:
      if (tls13_send_server_hello(ssl)) {
        hs->state = HS_STATE_SERVER_ENCRYPTED_EXTENSIONS;
        hs->interrupt = hs_interrupt_write;
      }
      break;
    case HS_STATE_SERVER_ENCRYPTED_EXTENSIONS:
      if (tls13_send_encrypted_extensions(ssl)) {
        if (ssl->s3->tmp.new_cipher->algorithm_auth & SSL_aPSK) {
          hs->state = HS_STATE_SERVER_FINISHED;
          hs->interrupt = hs_interrupt_write_flight;
        } else if (ssl->verify_mode & SSL_VERIFY_PEER) {
          hs->state = HS_STATE_SERVER_CERTIFICATE_REQUEST;
          hs->interrupt = hs_interrupt_write;
        } else {
          hs->state = HS_STATE_SERVER_CERTIFICATE;
          hs->interrupt = hs_interrupt_write;
        }
      }
      break;
    case HS_STATE_SERVER_CERTIFICATE_REQUEST:
      if (tls13_send_certificate_request(ssl)) {
        hs->state = HS_STATE_SERVER_CERTIFICATE;
        hs->interrupt = hs_interrupt_write;
      }
      break;
    case HS_STATE_SERVER_CERTIFICATE:
      if (!ssl_has_certificate(ssl)) {
        OPENSSL_PUT_ERROR(SSL, SSL_R_NO_CERTIFICATE_SET);
        return 0;
      }
      if (tls13_send_certificate(ssl)) {
        hs->state = HS_STATE_SERVER_CERTIFICATE_VERIFY;
        hs->interrupt = hs_interrupt_write;
      }
      break;
    case HS_STATE_SERVER_CERTIFICATE_VERIFY:
      if (tls13_send_certificate_verify(ssl)) {
        hs->state = HS_STATE_SERVER_FINISHED;
        hs->interrupt = hs_interrupt_write;
      }
      break;
    case HS_STATE_SERVER_FINISHED:
      if (tls13_send_finished(ssl)) {
        /* Update the secret to the master secret and derive traffic keys. */
        static const uint8_t kZeroes[EVP_MAX_MD_SIZE] = {0};
        size_t hash_len =
            EVP_MD_size(ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl)));
        if (!tls13_advance_key_schedule(ssl, kZeroes, hash_len) ||
            !tls13_derive_traffic_secret_0(ssl)) {
          return 0;
        }
        hs->state = HS_STATE_SERVER_FLUSH;
        hs->interrupt = hs_interrupt_write_flight;
      }
      break;
    case HS_STATE_SERVER_FLUSH:
      /* Set the outgoing traffic keys as soon as the Finished message is sent.
       * Otherwise alerts will be sent with the wrong keys. */
      if (!tls13_set_traffic_key(ssl, type_data, evp_aead_seal,
                                 hs->traffic_secret_0, hs->hash_len)) {
        return 0;
      }
      if (ssl->s3->tmp.cert_request) {
        hs->state = HS_STATE_CLIENT_CERTIFICATE;
        hs->interrupt = hs_interrupt_read;
      } else {
        hs->state = HS_STATE_CLIENT_FINISHED;
        hs->interrupt = hs_interrupt_read;
      }
      break;
    case HS_STATE_CLIENT_CERTIFICATE:
      if (ssl->s3->tmp.message_type != SSL3_MT_CERTIFICATE) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_certificate(ssl)) {
        ssl->method->hash_current_message(ssl);
        hs->state = ssl->session->peer == NULL
                                  ? HS_STATE_CLIENT_FINISHED
                                  : HS_STATE_CLIENT_CERTIFICATE_VERIFY;
        hs->interrupt = hs_interrupt_read;
      }
      break;
    case HS_STATE_CLIENT_CERTIFICATE_VERIFY:
      if (ssl->s3->tmp.message_type != SSL3_MT_CERTIFICATE_VERIFY) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_certificate_verify(ssl)) {
        ssl->method->hash_current_message(ssl);
        hs->state = HS_STATE_CLIENT_FINISHED;
        hs->interrupt = hs_interrupt_read;
      }
      break;
    case HS_STATE_CLIENT_FINISHED:
      if (ssl->s3->tmp.message_type != SSL3_MT_FINISHED) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_finished(ssl)) {
        ssl->method->hash_current_message(ssl);
        hs->state = HS_STATE_FINISH;
        hs->interrupt = hs_interrupt_none;
      }
      break;
    case HS_STATE_FINISH:
      /* evp_aead_seal keys have already been switched. */
      if (!tls13_set_traffic_key(ssl, type_data, evp_aead_open,
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
