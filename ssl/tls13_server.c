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

#include <openssl/hkdf.h>
#include <openssl/ssl.h>

#include <assert.h>
#include <string.h>

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
      // TODO: X509 Lookup
      ssl->rwstate = SSL_X509_LOOKUP;
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

  const uint8_t *psk_buf = NULL;
  const uint8_t *key_share_buf = NULL;
  const uint8_t *early_data_buf = NULL;
  size_t psk_len = 0, key_share_len = 0, early_data_len = 0;
  CBS psk, key_share, early_data;

  SSL_early_callback_ctx_extension_get(&early_ctx, TLSEXT_TYPE_pre_shared_key,
                                       &psk_buf, &psk_len);
  CBS_init(&psk, psk_buf, psk_len);
  SSL_early_callback_ctx_extension_get(&early_ctx, TLSEXT_TYPE_key_share,
                                       &key_share_buf, &key_share_len);
  CBS_init(&key_share, key_share_buf, key_share_len);
  SSL_early_callback_ctx_extension_get(&early_ctx, TLSEXT_TYPE_early_data,
                                       &early_data_buf, &early_data_len);
  CBS_init(&early_data, early_data_buf, early_data_len);

  uint8_t out_alert;
  if (!ext_pre_shared_key_parse_clienthello(ssl, &out_alert, &psk) ||
      !ext_key_share_parse_clienthello(ssl, &out_alert, &key_share) ||
      !ext_early_data_parse_clienthello(ssl, &out_alert, &early_data)) {
    alert = out_alert;
    OPENSSL_PUT_ERROR(SSL, SSL_R_ERROR_PARSING_EXTENSION);
    goto fatal_err;
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
  return -1;
}

static int tls13_send_server_hello(SSL *ssl, SSL_HS_MESSAGE *out) {
  CBB cbb;
  CBB_zero(&cbb);

  uint8_t *data;
  size_t length;
  if (!CBB_init(&cbb, 0) ||
      !CBB_add_u16(&cbb, ssl->version) ||
      !ssl_fill_hello_random(ssl->s3->server_random,
                             sizeof(ssl->s3->server_random),
                             0) ||
      !CBB_add_bytes(&cbb, ssl->s3->server_random, SSL3_RANDOM_SIZE) ||
      !CBB_add_u16(&cbb, ssl_cipher_get_value(ssl->s3->hs->cipher)) ||
      !ssl_add_serverhello_tlsext(ssl, &cbb) ||
      !CBB_finish(&cbb, &data, &length)) {
    goto err;
  }

  CBB_cleanup(&cbb);
  int ret = assemble_handshake_message(out, SSL3_MT_SERVER_HELLO, data, length);
  OPENSSL_free(data);
  return ret;

err:
  CBB_cleanup(&cbb);
  return -1;
}

static int tls13_send_encrypted_extensions(SSL *ssl, SSL_HS_MESSAGE *out) {
  if (!tls13_update_traffic_secret(ssl, type_handshake)) {
    return -1;
  }

  CBB cbb;
  CBB_zero(&cbb);

  uint8_t *data;
  size_t length;
  if (!CBB_init(&cbb, 0) ||
      !ssl_add_serverhello_tlsext(ssl, &cbb) ||
      !CBB_finish(&cbb, &data, &length)) {
    goto err;
  }

  CBB_cleanup(&cbb);
  int ret = assemble_handshake_message(out, SSL3_MT_ENCRYPTED_EXTENSIONS, data, length);
  OPENSSL_free(data);
  return ret;

err:
  CBB_cleanup(&cbb);
  return -1;
}

static int tls13_send_certificate_request(SSL *ssl, SSL_HS_MESSAGE *out) {
  // TODO(IMPLEMENT)
  int ret = assemble_handshake_message(out, SSL3_MT_CERTIFICATE_REQUEST, NULL, 0);
  return ret;
}

int tls13_server_handshake(SSL *ssl, SSL_HANDSHAKE *hs) {
  int result = 1;

  ERR_clear_system_error();
  assert(ssl->server);

  void (*cb)(const SSL *ssl, int type, int value) = NULL;
  if (ssl->info_callback != NULL) {
    cb = ssl->info_callback;
  } else if (ssl->ctx->info_callback != NULL) {
    cb = ssl->ctx->info_callback;
  }

  if (EVP_MD_CTX_md(&ssl->s3->handshake_hash) != NULL) {
  EVP_MD_CTX hh;
  EVP_MD_CTX_init(&hh);
  if (!EVP_MD_CTX_copy_ex(&hh, &ssl->s3->handshake_hash)) {
    return 0;
  }

  uint8_t *hs_hash = OPENSSL_malloc(EVP_MD_size(hh.digest));
  unsigned int hs_hash_len;
  if (!EVP_DigestFinal_ex(&hh, hs_hash, &hs_hash_len)) {
    return 0;
  }
  printf("HASH: ");
  size_t i;
  for (i = 0; i < hs_hash_len; i++) {
    printf("%02x", hs_hash[i]);
  }
  printf("\n");
  }


  switch (hs->handshake_state) {
    case HS_STATE_CLIENT_HELLO:
      if (hs->in_message->type != SSL3_MT_CLIENT_HELLO) {
        result = 0;
        break;
      }
      result = tls13_receive_client_hello(ssl, *hs->in_message);
      if (ssl->rwstate == SSL_X509_LOOKUP) {
        hs->handshake_interrupt = HS_NEED_CB;
        break;
      }
      hs->handshake_state = HS_STATE_SERVER_HELLO;
      hs->handshake_interrupt = HS_NEED_NONE;
      break;
    case HS_STATE_SERVER_HELLO:
      result = tls13_send_server_hello(ssl, hs->out_message);
      hs->handshake_state = HS_STATE_SERVER_ENCRYPTED_EXTENSIONS;
      hs->handshake_interrupt = HS_NEED_WRITE | HS_NEED_HASH;
      break;
    case HS_STATE_SERVER_ENCRYPTED_EXTENSIONS:
      result = tls13_send_encrypted_extensions(ssl, hs->out_message);
      if (hs->cipher->algorithm_auth & SSL_aPSK) {
        hs->handshake_state = HS_STATE_SERVER_FINISHED;
        hs->handshake_interrupt = HS_NEED_WRITE_FLIGHT;
      } else if (ssl->verify_mode & SSL_VERIFY_PEER) {
        hs->handshake_state = HS_STATE_SERVER_CERTIFICATE_REQUEST;
        hs->handshake_interrupt = HS_NEED_WRITE;
      } else {
        hs->handshake_state = HS_STATE_SERVER_CERTIFICATE;
        hs->handshake_interrupt = HS_NEED_WRITE;
      }
      break;
    case HS_STATE_SERVER_CERTIFICATE_REQUEST:
      result = tls13_send_certificate_request(ssl, hs->out_message);
      hs->handshake_state = HS_STATE_SERVER_CERTIFICATE;
      hs->handshake_interrupt = HS_NEED_WRITE;
      break;
    case HS_STATE_SERVER_CERTIFICATE:
      result = tls13_send_certificate(ssl, hs->out_message);
      hs->handshake_state = HS_STATE_SERVER_CERTIFICATE_VERIFY;
      hs->handshake_interrupt = HS_NEED_WRITE | HS_NEED_HASH;
      break;
    case HS_STATE_SERVER_CERTIFICATE_VERIFY:
      result = tls13_send_certificate_verify(ssl, hs->out_message);
      hs->handshake_state = HS_STATE_SERVER_FINISHED;
      hs->handshake_interrupt = HS_NEED_WRITE | HS_NEED_HASH;
      break;
    case HS_STATE_SERVER_FINISHED:
      result = tls13_send_finished(ssl, hs->out_message);
      if (!hs->cert_context) {
        hs->handshake_state = HS_STATE_CLIENT_FINISHED;
      } else {
        hs->handshake_state = HS_STATE_CLIENT_CERTIFICATE;
      }
      hs->handshake_interrupt = HS_NEED_WRITE_FLIGHT | HS_NEED_READ | HS_NEED_HASH;
      break;
    case HS_STATE_CLIENT_CERTIFICATE:
      if (!tls13_derive_traffic_secret_0(ssl)) {
        result = -1;
        break;
      }
      if (hs->in_message->type != SSL3_MT_CERTIFICATE) {
        result = 0;
        break;
      }
      result = tls13_receive_certificate(ssl, *hs->in_message);
      hs->handshake_state = HS_STATE_CLIENT_CERTIFICATE_VERIFY;
      hs->handshake_interrupt = HS_NEED_READ;

      break;
    case HS_STATE_CLIENT_CERTIFICATE_VERIFY:
      if (hs->in_message->type != SSL3_MT_CERTIFICATE_VERIFY) {
        result = 0;
        break;
      }
      result = tls13_receive_certificate_verify(ssl, *hs->in_message);
      hs->handshake_state = HS_STATE_CLIENT_FINISHED;
      hs->handshake_interrupt = HS_NEED_READ;
      break;
    case HS_STATE_CLIENT_FINISHED:
      if (!hs->cert_context) {
        if (!tls13_derive_traffic_secret_0(ssl)) {
          result = -1;
          break;
        }
      }
      result = tls13_receive_finished(ssl, *hs->in_message);
      hs->handshake_state = HS_STATE_FINISH;
      hs->handshake_interrupt = HS_NEED_NONE;
      break;
    case HS_STATE_FINISH:
      if (!tls13_finalize_keys(ssl)) {
        result = -1;
        break;
      }
      hs->handshake_state = HS_STATE_DONE;
      hs->handshake_interrupt = HS_NEED_NONE;
    default:
      break;
  }

  if (cb != NULL) {
    cb(ssl, SSL_CB_CONNECT_LOOP, result);
  }
  return result;
}

int tls13_server_post_handshake(SSL *ssl, SSL_HS_MESSAGE msg) {
  switch (msg.type) {
    case SSL3_MT_KEY_UPDATE:
      return tls13_receive_key_update(ssl, msg);
    default:
      return 0;
  }
}
