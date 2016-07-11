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

static int ssl_write_client_cipher_list(SSL *ssl, CBB *out,
                                        uint16_t min_version,
                                        uint16_t max_version);

static int tls13_send_client_hello(SSL *ssl) {
  uint16_t min_version, max_version;
  if (!ssl_get_version_range(ssl, &min_version, &max_version)) {
    return 0;
  }

  if (!ssl->s3->have_version) {
    ssl->version = ssl->method->version_to_wire(max_version);
    ssl->client_version = ssl->version;
  }

  CBB outer, cbb, child;
  if (!ssl->method->init_message(ssl, &outer, &cbb, SSL3_MT_CLIENT_HELLO) ||
      !CBB_add_u16(&cbb, ssl->client_version) ||
      !RAND_bytes(ssl->s3->client_random, sizeof(ssl->s3->client_random)) ||
      !CBB_add_bytes(&cbb, ssl->s3->client_random, SSL3_RANDOM_SIZE) ||
      !CBB_add_u8_length_prefixed(&cbb, &child) ||
      !ssl_write_client_cipher_list(ssl, &cbb, min_version, max_version) ||
      !CBB_add_u8(&cbb, 1) ||
      !CBB_add_u8(&cbb, 0) ||
      !ssl_add_clienthello_tlsext(ssl, &cbb, 0) ||
      !ssl->method->finish_message(ssl, &outer)) {
    CBB_cleanup(&outer);
    return 0;
  }

  if (!ssl3_init_handshake_buffer(ssl)) {
    return 0;
  }

  return 1;
}

static int tls13_receive_server_hello(SSL *ssl, SSL_HS_MESSAGE msg) {
  int alert;

  CBS cbs;
  CBS_init(&cbs, msg.data, msg.length);

  CBS server_random;
  uint16_t server_wire_version, server_version;
  uint16_t cipher_suite;
  if (!CBS_get_u16(&cbs, &server_wire_version) ||
      !CBS_get_bytes(&cbs, &server_random, SSL3_RANDOM_SIZE) ||
      !CBS_get_u16(&cbs, &cipher_suite)) {
    alert = SSL_AD_DECODE_ERROR;
    goto fatal_err;
  }

  server_version = ssl->method->version_from_wire(server_wire_version);

  if (!ssl->s3->have_version) {
    uint16_t min_version, max_version;
    if (!ssl_get_version_range(ssl, &min_version, &max_version) ||
        server_version < min_version || server_version > max_version ||
        (ssl->s3->hs->zero_rtt == 1 &&
         ssl3_protocol_version(ssl) < TLS1_3_VERSION)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_UNSUPPORTED_PROTOCOL);
      alert = SSL_AD_PROTOCOL_VERSION;
      goto fatal_err;
    }
    ssl->version = server_wire_version;
    ssl->s3->enc_method = ssl3_get_enc_method(server_version);
    assert(ssl->s3->enc_method != NULL);
    /* At this point, the connection's version is known and ssl->version is
     * fixed. Begin enforcing the record-layer version. */
    ssl->s3->have_version = 1;
  } else if (server_wire_version != ssl->version) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_SSL_VERSION);
    alert = SSL_AD_PROTOCOL_VERSION;
    goto fatal_err;
  }

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
  ssl->s3->hs->resumption_ctx = OPENSSL_malloc(ssl->s3->hs->key_len);
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

static int tls13_receive_encrypted_extensions(SSL *ssl, SSL_HS_MESSAGE msg) {
  int alert = 0;

  CBS cbs;
  CBS_init(&cbs, msg.data, msg.length);

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

static int ca_dn_cmp(const X509_NAME **a, const X509_NAME **b) {
  return X509_NAME_cmp(*a, *b);
}

static int tls13_receive_certificate_request(SSL *ssl, SSL_HS_MESSAGE msg) {
  int ret = 0;
  X509_NAME *xn = NULL;
  STACK_OF(X509_NAME) *ca_sk = NULL;

  ssl->s3->tmp.cert_request = 0;

  CBS cbs;
  CBS_init(&cbs, msg.data, msg.length);

  ca_sk = sk_X509_NAME_new(ca_dn_cmp);
  if (ca_sk == NULL) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  CBS context, supported_signature_algorithms;
  if (!CBS_get_u8_length_prefixed(&cbs, &context) ||
      !CBS_stow(&context, &ssl->s3->hs->cert_context, &ssl->s3->hs->cert_context_len) ||
      !CBS_get_u16_length_prefixed(&cbs, &supported_signature_algorithms) ||
      !tls1_parse_peer_sigalgs(ssl, &supported_signature_algorithms)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    goto err;
  }

  /* get the CA RDNs */
  CBS certificate_authorities;
  if (!CBS_get_u16_length_prefixed(&cbs, &certificate_authorities)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    OPENSSL_PUT_ERROR(SSL, SSL_R_LENGTH_MISMATCH);
    goto err;
  }

  while (CBS_len(&certificate_authorities) > 0) {
    CBS distinguished_name;
    if (!CBS_get_u16_length_prefixed(&certificate_authorities,
                                     &distinguished_name)) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
      OPENSSL_PUT_ERROR(SSL, SSL_R_CA_DN_TOO_LONG);
      goto err;
    }

    const uint8_t *data = CBS_data(&distinguished_name);
    /* A u16 length cannot overflow a long. */
    xn = d2i_X509_NAME(NULL, &data, (long)CBS_len(&distinguished_name));
    if (xn == NULL ||
        data != CBS_data(&distinguished_name) + CBS_len(&distinguished_name)) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
      OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
      goto err;
    }

    if (!sk_X509_NAME_push(ca_sk, xn)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      goto err;
    }
    xn = NULL;
  }

  // TODO(svaldez): certificate_extensions

  ret = 1;

err:
  X509_NAME_free(xn);
  sk_X509_NAME_pop_free(ca_sk, X509_NAME_free);
  return ret;
}

// REST

static int ssl_write_client_cipher_list(SSL *ssl, CBB *out,
                                         uint16_t min_version,
                                         uint16_t max_version) {

  /* Prepare disabled cipher masks. */
  ssl_set_client_disabled(ssl);

  CBB child;
  if (!CBB_add_u16_length_prefixed(out, &child)) {
    return 0;
  }

  STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(ssl);

  int any_enabled = 0;
  size_t i;
  for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
    const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
    /* Skip disabled ciphers */
    if ((cipher->algorithm_mkey & ssl->cert->mask_k) ||
        (cipher->algorithm_auth & ssl->cert->mask_a)) {
      continue;
    }
    if (SSL_CIPHER_get_min_version(cipher) > max_version ||
        SSL_CIPHER_get_max_version(cipher) < min_version) {
      continue;
    }
    any_enabled = 1;
    if (!CBB_add_u16(&child, ssl_cipher_get_value(cipher))) {
      return 0;
    }
  }

  /* If all ciphers were disabled, return the error to the caller. */
  if (!any_enabled) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_CIPHERS_AVAILABLE);
    return 0;
  }

  /* For SSLv3, the SCSV is added. Otherwise the renegotiation extension is
   * added. */
  if (ssl->client_version == SSL3_VERSION &&
      !ssl->s3->initial_handshake_complete) {
    if (!CBB_add_u16(&child, SSL3_CK_SCSV & 0xffff)) {
      return 0;
    }
    /* The renegotiation extension is required to be at index zero. */
    ssl->s3->tmp.extensions.sent |= (1u << 0);
  }

  if ((ssl->mode & SSL_MODE_SEND_FALLBACK_SCSV) &&
      !CBB_add_u16(&child, SSL3_CK_FALLBACK_SCSV & 0xffff)) {
    return 0;
  }

  return CBB_flush(out);
}

int tls13_client_handshake(SSL *ssl, SSL_HANDSHAKE *hs) {
  ERR_clear_system_error();
  assert(!ssl->server);

  hs->handshake_interrupt |= HS_NEED_ERROR;

  switch (hs->handshake_state) {
    case HS_STATE_CLIENT_HELLO:
      if (tls13_send_client_hello(ssl)) {
        if (hs->zero_rtt) {
          hs->handshake_state = HS_STATE_CLIENT_ENCRYPTED_EXTENSIONS;
          hs->handshake_interrupt = HS_NEED_WRITE;
        } else {
          hs->handshake_state = HS_STATE_SERVER_HELLO;
          hs->handshake_interrupt = HS_NEED_WRITE_FLIGHT | HS_NEED_READ;
        }
      }
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
      if (hs->in_message->type == SSL3_MT_HELLO_RETRY_REQUEST) {
        /* TODO(svaldez): Handle HelloRetryRequest (might kill 0-RTT) */
      }
      if (hs->in_message->type != SSL3_MT_SERVER_HELLO) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_server_hello(ssl, *hs->in_message)) {
        hs->handshake_state = HS_STATE_SERVER_ENCRYPTED_EXTENSIONS;
        hs->handshake_interrupt = HS_NEED_READ;
      }
      break;
    case HS_STATE_SERVER_ENCRYPTED_EXTENSIONS:
      if (hs->in_message->type != SSL3_MT_ENCRYPTED_EXTENSIONS) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_encrypted_extensions(ssl, *hs->in_message)) {
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
      if (hs->in_message->type == SSL3_MT_CERTIFICATE_REQUEST) {
        hs->client_auth = 1;
        if (tls13_receive_certificate_request(ssl, *hs->in_message)) {
          hs->handshake_state = HS_STATE_SERVER_CERTIFICATE;
          hs->handshake_interrupt = HS_NEED_READ;
        }
      } else {
        hs->handshake_state = HS_STATE_SERVER_CERTIFICATE;
        hs->handshake_interrupt = HS_NEED_NONE;
      }
      break;
    case HS_STATE_SERVER_CERTIFICATE:
      if (hs->in_message->type != SSL3_MT_CERTIFICATE) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_certificate(ssl, *hs->in_message)) {
        hs->handshake_state = HS_STATE_SERVER_CERTIFICATE_VERIFY;
        hs->handshake_interrupt = HS_NEED_READ;
      }
      break;
    case HS_STATE_SERVER_CERTIFICATE_VERIFY:
      if (hs->in_message->type != SSL3_MT_CERTIFICATE_VERIFY) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_certificate_verify(ssl, *hs->in_message)) {
        if (!tls13_store_handshake_context(ssl)) {
          return 0;
        }
        hs->handshake_state = HS_STATE_SERVER_FINISHED;
        hs->handshake_interrupt = HS_NEED_READ;
      }
      break;
    case HS_STATE_SERVER_FINISHED:
      if (hs->in_message->type != SSL3_MT_FINISHED) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
        return 0;
      }
      if (tls13_receive_finished(ssl, *hs->in_message)) {
        if (!tls13_store_handshake_context(ssl) ||
            !tls13_derive_traffic_secret_0(ssl)) {
          return 0;
        }
        if (hs->client_auth) {
          hs->handshake_state = HS_STATE_CLIENT_CERTIFICATE;
        } else {
          hs->handshake_state = HS_STATE_CLIENT_FINISHED;
        }
        hs->handshake_interrupt = HS_NEED_NONE;
      }
      break;
    case HS_STATE_CLIENT_CERTIFICATE:
      if (tls13_send_certificate(ssl)) {
        hs->handshake_state = HS_STATE_CLIENT_CERTIFICATE_VERIFY;
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
