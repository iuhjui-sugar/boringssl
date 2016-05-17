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
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../ssl/internal.h"
#include "../crypto/dh/internal.h"

static int ssl_write_client_cipher_list(SSL *ssl, CBB *out);

int tls13_client_handshake(SSL *ssl) {
  int result = 1;

  ERR_clear_system_error();
  assert(!ssl->server);

  void (*cb)(const SSL *ssl, int type, int value) = NULL;
  if (ssl->info_callback != NULL) {
    cb = ssl->info_callback;
  } else if (ssl->ctx->info_callback != NULL) {
    cb = ssl->ctx->info_callback;
  }

  switch (ssl->hs->handshake_state) {
    case HS_STATE_CONNECT:
      result = tls13_send_client_hello(ssl, ssl->hs->out_message);
      ssl->hs->handshake_state = HS_STATE_RECV_SERVER_HELLO;
      ssl->hs->handshake_interrupt = HS_NEED_WRITE | HS_NEED_READ;
      break;
    case HS_STATE_RECV_SERVER_HELLO:
      if (ssl->hs->in_message->type != SSL3_MT_SERVER_HELLO) {
        result = 0;
        break;
      }
      result = tls13_receive_server_hello(ssl, *ssl->hs->in_message);
      ssl->hs->handshake_state = HS_STATE_RECV_ENCRYPTED_EXTENSIONS;
      ssl->hs->handshake_interrupt = HS_NEED_READ;
      break;
    case HS_STATE_RECV_ENCRYPTED_EXTENSIONS:
      if (ssl->hs->in_message->type != SSL3_MT_ENCRYPTED_EXTENSIONS) {
        result = 0;
        break;
      }
      result = tls13_receive_encrypted_extensions(ssl, *ssl->hs->in_message);
      if (ssl->hs->cipher->algorithm_auth & SSL_aPSK) {
        ssl->hs->handshake_state = HS_STATE_RECV_FINISHED;
      } else {
        ssl->hs->handshake_state = HS_STATE_RECV_CERTIFICATE_REQUEST;
      }
      ssl->hs->handshake_interrupt = HS_NEED_READ;
      break;
    case HS_STATE_RECV_CERTIFICATE_REQUEST:
      if (ssl->hs->in_message->type == SSL3_MT_CERTIFICATE_REQUEST) {
        result = tls13_receive_certificate_request(ssl, *ssl->hs->in_message);
        ssl->hs->handshake_interrupt = HS_NEED_READ;
      } else {
        result = 1;
        ssl->hs->handshake_interrupt = HS_NEED_NONE;
      }
      ssl->hs->handshake_state = HS_STATE_RECV_CERTIFICATE;
      break;
    case HS_STATE_RECV_CERTIFICATE:
      if (ssl->hs->in_message->type != SSL3_MT_CERTIFICATE) {
        result = 0;
        break;
      }
      result = tls13_receive_certificate(ssl, *ssl->hs->in_message);
      ssl->hs->handshake_state = HS_STATE_RECV_CERTIFICATE_VERIFY;
      ssl->hs->handshake_interrupt = HS_NEED_READ;
      break;
    case HS_STATE_RECV_CERTIFICATE_VERIFY:
      if (ssl->hs->in_message->type != SSL3_MT_CERTIFICATE_VERIFY) {
        result = 0;
        break;
      }
      result = tls13_receive_certificate_verify(ssl, *ssl->hs->in_message);
      ssl->hs->handshake_state = HS_STATE_RECV_FINISHED;
      ssl->hs->handshake_interrupt = HS_NEED_READ;
      break;
    case HS_STATE_RECV_FINISHED:
      if (ssl->hs->in_message->type != SSL3_MT_FINISHED) {
        result = 0;
        break;
      }
      result = tls13_receive_finished(ssl, *ssl->hs->in_message);
      if (ssl->hs->cipher->algorithm_auth & SSL_aPSK) {
        ssl->hs->handshake_state = HS_STATE_SEND_FINISHED;
      } else {
        ssl->hs->handshake_state = HS_STATE_SEND_CERTIFICATE;
      }
      ssl->hs->handshake_interrupt = HS_NEED_NONE;
      break;
    case HS_STATE_SEND_CERTIFICATE:
      result = tls13_send_certificate(ssl, ssl->hs->out_message);
      ssl->hs->handshake_state = HS_STATE_SEND_CERTIFICATE_VERIFY;
      ssl->hs->handshake_interrupt = HS_NEED_WRITE;
      break;
    case HS_STATE_SEND_CERTIFICATE_VERIFY:
      result = tls13_send_certificate_verify(ssl, ssl->hs->out_message);
      ssl->hs->handshake_state = HS_STATE_SEND_FINISHED;
      ssl->hs->handshake_interrupt = HS_NEED_WRITE;
      break;
    case HS_STATE_SEND_FINISHED:
      result = tls13_send_finished(ssl, ssl->hs->out_message);
      ssl->hs->handshake_state = HS_STATE_DONE;
      ssl->hs->handshake_interrupt = HS_NEED_WRITE;
      break;
    default:
      break;
  }

  if (cb != NULL) {
    cb(ssl, SSL_CB_CONNECT_LOOP, result);
  }
  return result;
}

int tls13_send_client_hello(SSL *ssl, SSL_HS_MESSAGE *out) {
  CBB cbb;
  CBB_zero(&cbb);

  if (!ssl->s3->have_version) {
    uint16_t max_version = ssl3_get_max_client_version(ssl);
    if (max_version == 0) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_SSL_VERSION);
      goto err;
    }
    ssl->version = max_version;
    ssl->client_version = max_version;
  }

  CBB child;
  uint8_t *data;
  size_t length;
  if (!CBB_init(&cbb, 0) ||
      !CBB_add_u16(&cbb, ssl->client_version) ||
      !ssl_fill_hello_random(ssl->s3->client_random,
                             sizeof(ssl->s3->client_random),
                             0) ||
      !CBB_add_bytes(&cbb, ssl->s3->client_random, SSL3_RANDOM_SIZE) ||
      !CBB_add_u8_length_prefixed(&cbb, &child) ||
      !ssl_write_client_cipher_list(ssl, &cbb) ||
      !CBB_add_u8(&cbb, 1) ||
      !CBB_add_u8(&cbb, 0) ||
      !ssl_add_clienthello_tlsext(ssl, &cbb, 0) ||
      !CBB_finish(&cbb, &data, &length)) {
    goto err;
  }

  if (!ssl3_init_handshake_buffer(ssl)) {
    goto err;
  }

  return set_hs_message(out, SSL3_MT_CLIENT_HELLO, data, length);

err:
  CBB_cleanup(&cbb);
  return -1;
}

int tls13_receive_server_hello(SSL *ssl, SSL_HS_MESSAGE msg) {
  int alert;

  CBS cbs;
  CBS_init(&cbs, msg.data, msg.length);

  CBS server_random;
  uint16_t cipher_suite;
  if (!CBS_get_u16(&cbs, (uint16_t*)&ssl->version) ||
      !CBS_get_bytes(&cbs, &server_random, SSL3_RANDOM_SIZE) ||
      !CBS_get_u16(&cbs, &cipher_suite)) {
    goto fatal_err;
  }

  ssl->s3->have_version = 1;
  if (!ssl3_is_version_enabled(ssl, ssl->version)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNSUPPORTED_PROTOCOL);
    alert = SSL_AD_PROTOCOL_VERSION;
    goto fatal_err;
  }

  ssl->s3->enc_method = ssl3_get_enc_method(ssl->version);
  assert(ssl->s3->enc_method != NULL);

  memcpy(ssl->s3->server_random, CBS_data(&server_random), SSL3_RANDOM_SIZE);

  ssl->hit = 0;
  if (!ssl_get_new_session(ssl, 0)) {
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
      !sk_SSL_CIPHER_find(ssl_get_ciphers_by_id(ssl), NULL, cipher)) {
    alert = SSL_AD_ILLEGAL_PARAMETER;
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_CIPHER_RETURNED);
    goto fatal_err;
  }

  ssl->session->cipher = cipher;
  ssl->hs->cipher = cipher;
  ssl->s3->tmp.new_cipher = cipher;

  if (!ssl3_init_handshake_hash(ssl)) {
    goto err;
  }
  ssl3_free_handshake_buffer(ssl);

  /* TLS extensions */
  if (!ssl_parse_serverhello_tlsext(ssl, &cbs)) {
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

  if (!tls1_change_cipher_state(ssl, SSL3_CHANGE_CIPHER_CLIENT_READ)) {
    goto err;
  }

  return 1;

fatal_err:
  ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
err:
  return -1;
}

int tls13_receive_encrypted_extensions(SSL *ssl, SSL_HS_MESSAGE msg) {
  return 1;
}

int tls13_receive_certificate_request(SSL *ssl, SSL_HS_MESSAGE msg) {
  return 1;
}

int tls13_receive_certificate(SSL *ssl, SSL_HS_MESSAGE msg) {
  return 1;
}

int tls13_receive_certificate_verify(SSL *ssl, SSL_HS_MESSAGE msg) {
  return 1;
}

int tls13_receive_finished(SSL *ssl, SSL_HS_MESSAGE msg) {
  return 1;
}

int tls13_send_certificate(SSL *ssl, SSL_HS_MESSAGE *out) {
  return 1;
}

int tls13_send_certificate_verify(SSL *ssl, SSL_HS_MESSAGE *out) {
  return 1;
}

int tls13_send_finished(SSL *ssl, SSL_HS_MESSAGE *out) {
  return 1;
}

// REST

static int ssl_write_client_cipher_list(SSL *ssl, CBB *out) {
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
    if (SSL_CIPHER_get_min_version(cipher) >
        ssl3_version_from_wire(ssl, ssl->client_version)) {
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
