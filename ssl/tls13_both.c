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

#include <assert.h>
#include <string.h>

#include <openssl/hkdf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "internal.h"

int tls13_handshake(SSL *ssl) {
  SSL_HANDSHAKE *hs = ssl->s3->hs;

  int result = 1;
  while (result && hs->handshake_state != HS_STATE_DONE) {
    ssl->rwstate = SSL_NOTHING;

    if (hs->handshake_interrupt & HS_NEED_WRITE) {
      int ret = tls13_handshake_write(ssl, hs->out_message);
      if (ret <= 0) {
       ssl->rwstate = SSL_WRITING;
        return ret;
      }
      hs->handshake_interrupt &= ~HS_NEED_WRITE;
      if (hs->handshake_interrupt & HS_NEED_FLUSH) {
        if (!tls13_store_handshake_context(ssl)) {
          return -1;
        }
        return 1;
      }
    }
    if (hs->handshake_interrupt & HS_NEED_READ) {
      int ret = tls13_handshake_read(ssl, hs->in_message);
      if (ret <= 0) {
        ssl->rwstate = SSL_READING;
        return ret;
      }
      hs->handshake_interrupt &= ~HS_NEED_READ;
      printf("Server Message: %d\n", hs->in_message->type);
    }
    if (ssl->server) {
      result = tls13_server_handshake(ssl, hs);
    } else {
      result = tls13_client_handshake(ssl, hs);
    }

    if (ssl->s3->hs->handshake_interrupt & HS_NEED_WRITE) {
      printf("State: %d (Writing Message %d)\n", ssl->s3->hs->handshake_state, ssl->s3->hs->out_message->type);
    } else if (ssl->s3->hs->handshake_interrupt & HS_NEED_READ) {
      printf("State: %d (Reading Message)\n", ssl->s3->hs->handshake_state);
    }
  }

  return result;
}

int assemble_handshake_message(SSL_HS_MESSAGE *out, uint8_t type, uint8_t *data,
                               size_t length) {
  if (out->raw != NULL) {
    OPENSSL_free(out->raw);
    out->raw = NULL;
  }

  out->type = type;
  out->length = length;
  out->raw = OPENSSL_malloc(SSL3_HM_HEADER_LENGTH + out->length);
  if (out->raw == NULL) {
    return -1;
  }
  uint8_t *p = out->raw;
  *(p++) = out->type;
  l2n3(out->length, p);
  out->data = p;
  memcpy(out->data, data, out->length);
  out->offset = 0;

  return 1;
}

int tls13_handshake_read(SSL *ssl, SSL_HS_MESSAGE *msg) {
  int ok;
  long n = ssl->method->ssl_get_message(ssl, -1, ssl_dont_hash_message, &ok);

  if (!ok) {
    return n;
  }

  if (!assemble_handshake_message(msg, ssl->s3->tmp.message_type, ssl->init_msg,
                                  n)) {
    return -1;
  }

  ssl3_update_handshake_hash(ssl, msg->raw, n + SSL3_HM_HEADER_LENGTH);

  printf("IN: ");
  size_t i;
  for (i = 0; i < (size_t)(n + SSL3_HM_HEADER_LENGTH); i++) {
    printf("%02x", msg->raw[i]);
  }
  printf("\n");

  return 1;
}

int tls13_handshake_write(SSL *ssl, SSL_HS_MESSAGE *msg) {
  size_t length = SSL3_HM_HEADER_LENGTH + msg->length;

  if (!msg->offset) {
    CBB cbb, data;
    if (!CBB_init_fixed(&cbb, (uint8_t *)ssl->init_buf->data, length) ||
        !CBB_add_u8(&cbb, msg->type) ||
        !CBB_add_u24_length_prefixed(&cbb, &data) ||
        !CBB_add_bytes(&data, msg->data, msg->length) ||
        !CBB_finish(&cbb, NULL, NULL)) {
      return -1;
    }
    ssl->init_num = length;
    ssl->init_off = 0;
    msg->offset = 1;
  }

  int ret = ssl_do_write(ssl);
  if (ret <= 0) {
    return ret;
  }

  printf("OUT: ");
  size_t i;
  for (i = 0; i < length; i++) {
    printf("%02x", msg->raw[i]);
  }
  printf("\n");

  ssl3_update_handshake_hash(ssl, msg->raw, length);
  msg->offset = 0;
  return 1;
}

int tls13_post_handshake_read(SSL *ssl, uint8_t *buf, uint16_t len) {
  size_t buf_offset = 0;

  SSL_HS_MESSAGE *msg = ssl->s3->post_message;
  if (msg->offset < SSL3_HM_HEADER_LENGTH) {
    if (msg->raw != NULL) {
      OPENSSL_free(msg->raw);
      msg->raw = NULL;
    }

    if (msg->offset == 0) {
      msg->data = OPENSSL_malloc(SSL3_HM_HEADER_LENGTH);
    }

    size_t length = SSL3_HM_HEADER_LENGTH;
    size_t n = length - msg->offset;
    if (len - buf_offset < n) {
      n = len - buf_offset;
    }
    memcpy(&msg->data[msg->offset], &buf[buf_offset], n);

    msg->offset += n;
    buf_offset += n;
    if (msg->offset < length) {
      return 0;
    }

    uint8_t *p = msg->data;
    msg->type = *(p++);
    n2l3(p, msg->length);
    msg->raw = OPENSSL_malloc(SSL3_HM_HEADER_LENGTH + msg->length);
    if (msg->raw == NULL) {
      return -1;
    }
    memcpy(msg->raw, msg->data, SSL3_HM_HEADER_LENGTH);
    OPENSSL_free(msg->data);
    msg->data = &msg->raw[SSL3_HM_HEADER_LENGTH];
  }

  size_t length = SSL3_HM_HEADER_LENGTH + msg->length;
  size_t n = length - msg->offset;
  if (len - buf_offset < n) {
    n = len - buf_offset;
  }
  memcpy(&msg->raw[msg->offset], &buf[buf_offset], n);

  msg->offset += n;
  ssl3_update_handshake_hash(ssl, msg->raw, length);
  if (msg->offset < length) {
    return 0;
  }

  if (ssl->msg_callback) {
    ssl->msg_callback(0, ssl->version, SSL3_RT_HANDSHAKE, &msg->raw,
                      length, ssl, ssl->msg_callback_arg);
  }

  printf("PH IN: ");
  size_t i;
  for (i = 0; i < length; i++) {
    printf("%02x", msg->raw[i]);
  }
  printf("\n");

  msg->offset = 0;

  if (ssl->server) {
    if (!tls13_server_post_handshake(ssl, *msg)) {
      return -1;
    }
  } else {
    if (!tls13_client_post_handshake(ssl, *msg)) {
      return -1;
    }
  }
  return 1;
}

int tls13_store_handshake_context(SSL *ssl) {
  EVP_MD_CTX hh;
  EVP_MD_CTX_init(&hh);
  if (!EVP_MD_CTX_copy_ex(&hh, &ssl->s3->handshake_hash)) {
    EVP_MD_CTX_cleanup(&hh);
    return 0;
  }

  if (ssl->s3->hs->hs_context) {
    OPENSSL_free(ssl->s3->hs->hs_context);
  }

  ssl->s3->hs->hs_context = OPENSSL_malloc(EVP_MD_size(hh.digest));
  if (!EVP_DigestFinal_ex(&hh, ssl->s3->hs->hs_context,
                          &ssl->s3->hs->hs_context_len)) {
    EVP_MD_CTX_cleanup(&hh);
    return 0;
  }

  EVP_MD_CTX_cleanup(&hh);
  return 1;
}

// SHARED

/* ssl3_check_leaf_certificate returns one if |leaf| is a suitable leaf server
 * certificate for |ssl|. Otherwise, it returns zero and pushes an error on the
 * error queue. */
static int ssl3_check_leaf_certificate(SSL *ssl, X509 *leaf) {
  int ret = 0;
  EVP_PKEY *pkey = X509_get_pubkey(leaf);
  if (pkey == NULL) {
    goto err;
  }

  /* Check the certificate's type matches the cipher. */
  const SSL_CIPHER *cipher = ssl->s3->tmp.new_cipher;
  int expected_type = ssl_cipher_get_key_type(cipher);
  assert(expected_type != EVP_PKEY_NONE);
  if (pkey->type != expected_type) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_CERTIFICATE_TYPE);
    goto err;
  }

  if (cipher->algorithm_auth & SSL_aECDSA) {
    /* TODO(davidben): This behavior is preserved from upstream. Should key
     * usages be checked in other cases as well? */
    /* This call populates the ex_flags field correctly */
    X509_check_purpose(leaf, -1, 0);
    if ((leaf->ex_flags & EXFLAG_KUSAGE) &&
        !(leaf->ex_kusage & X509v3_KU_DIGITAL_SIGNATURE)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_ECC_CERT_NOT_FOR_SIGNING);
      goto err;
    }

    if (!tls1_check_ec_cert(ssl, leaf)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECC_CERT);
      goto err;
    }
  }

  ret = 1;

err:
  EVP_PKEY_free(pkey);
  return ret;
}

int tls13_receive_certificate(SSL *ssl, SSL_HS_MESSAGE msg) {
  int al, ret = -1;
  X509 *x = NULL;
  STACK_OF(X509) *sk = NULL;
  EVP_PKEY *pkey = NULL;
  CBS certificate_list;
  const uint8_t *data;

  sk = sk_X509_new_null();
  if (sk == NULL) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  CBS cbs;
  CBS_init(&cbs, msg.data, msg.length);

  CBS context;
  if (!CBS_get_u8_length_prefixed(&cbs, &context) ||
      CBS_len(&context) != 0) {
    al = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    goto f_err;
  }

  if (!CBS_get_u24_length_prefixed(&cbs, &certificate_list) ||
      CBS_len(&certificate_list) == 0 ||
      CBS_len(&cbs) != 0) {
    al = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    goto f_err;
  }

  while (CBS_len(&certificate_list) > 0) {
    CBS certificate;
    if (!CBS_get_u24_length_prefixed(&certificate_list, &certificate)) {
      al = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_CERT_LENGTH_MISMATCH);
      goto f_err;
    }
    /* A u24 length cannot overflow a long. */
    data = CBS_data(&certificate);
    x = d2i_X509(NULL, &data, (long)CBS_len(&certificate));
    if (x == NULL) {
      al = SSL_AD_BAD_CERTIFICATE;
      OPENSSL_PUT_ERROR(SSL, ERR_R_ASN1_LIB);
      goto f_err;
    }
    if (data != CBS_data(&certificate) + CBS_len(&certificate)) {
      al = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_CERT_LENGTH_MISMATCH);
      goto f_err;
    }
    if (!sk_X509_push(sk, x)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      goto err;
    }
    x = NULL;
  }

  X509 *leaf = sk_X509_value(sk, 0);
  if (!ssl3_check_leaf_certificate(ssl, leaf)) {
    al = SSL_AD_ILLEGAL_PARAMETER;
    goto f_err;
  }

  /* NOTE: Unlike the server half, the client's copy of |cert_chain| includes
   * the leaf. */
  sk_X509_pop_free(ssl->session->cert_chain, X509_free);
  ssl->session->cert_chain = sk;
  sk = NULL;

  X509_free(ssl->session->peer);
  ssl->session->peer = X509_up_ref(leaf);

  ssl->session->verify_result = ssl->verify_result;

  ret = 1;

  if (0) {
  f_err:
    ssl3_send_alert(ssl, SSL3_AL_FATAL, al);
  }

err:
  EVP_PKEY_free(pkey);
  X509_free(x);
  sk_X509_pop_free(sk, X509_free);
  return ret;
}

int tls13_receive_certificate_verify(SSL *ssl, SSL_HS_MESSAGE msg) {
  int al, ret = 0;
  X509 *peer = ssl->session->peer;
  EVP_PKEY *pkey = NULL;
  const EVP_MD *md = NULL;
  uint8_t digest[EVP_MAX_MD_SIZE];
  size_t digest_length;
  EVP_PKEY_CTX *pctx = NULL;

  CBS cbs;
  CBS_init(&cbs, msg.data, msg.length);

  /* Filter out unsupported certificate types. */
  pkey = X509_get_pubkey(peer);
  if (pkey == NULL) {
    goto err;
  }
  if (!(X509_certificate_type(peer, pkey) & EVP_PKT_SIGN) ||
      (pkey->type != EVP_PKEY_RSA && pkey->type != EVP_PKEY_EC)) {
    al = SSL_AD_UNSUPPORTED_CERTIFICATE;
    OPENSSL_PUT_ERROR(SSL, SSL_R_PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE);
    goto f_err;
  }

  uint8_t hash, signature_type;
  if (!CBS_get_u8(&cbs, &hash) ||
      !CBS_get_u8(&cbs, &signature_type)) {
    al = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    goto f_err;
  }
  if (!tls12_check_peer_sigalg(ssl, &md, &al, hash, signature_type, pkey)) {
    goto f_err;
  }

  if (!tls13_cert_verify_digest(ssl, digest, &digest_length, !ssl->server, md)) {
    goto err;
  }

  CBS signature;
  if (!CBS_get_u16_length_prefixed(&cbs, &signature) ||
      CBS_len(&cbs) != 0) {
    al = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    goto f_err;
  }

  pctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (pctx == NULL) {
    goto err;
  }
  int sig_ok = EVP_PKEY_verify_init(pctx) &&
               EVP_PKEY_CTX_set_signature_md(pctx, md) &&
               EVP_PKEY_verify(pctx, CBS_data(&signature), CBS_len(&signature),
                               digest, digest_length);

  if (!sig_ok) {
    al = SSL_AD_DECRYPT_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_SIGNATURE);
    goto f_err;
  }

  ret = 1;

  if (0) {
  f_err:
    ssl3_send_alert(ssl, SSL3_AL_FATAL, al);
  }

err:
  EVP_PKEY_CTX_free(pctx);
  EVP_PKEY_free(pkey);

  return ret;
}

int tls13_receive_finished(SSL *ssl, SSL_HS_MESSAGE msg) {
  size_t signature_len;
  uint8_t *signature = OPENSSL_malloc(EVP_MAX_MD_SIZE);

  if (!tls13_verify_finished(ssl, signature, &signature_len, !ssl->server)) {
    goto f_err;
  }

  if (msg.length != signature_len ||
      CRYPTO_memcmp(signature, msg.data, signature_len) != 0) {
    goto f_err;
  }

  OPENSSL_free(signature);
  return 1;

f_err:
  OPENSSL_free(signature);
  ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECRYPT_ERROR);
  OPENSSL_PUT_ERROR(SSL, SSL_R_DIGEST_CHECK_FAILED);
  return 0;
}

static int tls13_write_cert(CBB *cbb, X509 *cert) {
  uint8_t *buf;
  int len = i2d_X509(cert, NULL);

  if (len < 0 ||
      !CBB_add_space(cbb, &buf, len) ||
      i2d_X509(cert, &buf) < 0) {
    return 0;
  }

  return 1;
}

static int tls13_write_server_cert_chain(SSL *ssl, CBB *cbb) {
  CERT *cert = ssl->cert;
  int no_chain = 0;
  size_t i;
  CBB child;

  X509 *x = cert->x509;
  STACK_OF(X509) *chain = cert->chain;

  if (x == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_CERTIFICATE_SET);
    return 0;
  }

  if ((ssl->mode & SSL_MODE_NO_AUTO_CHAIN) || chain != NULL) {
    no_chain = 1;
  }

  if (no_chain) {
    if (!CBB_add_u24_length_prefixed(cbb, &child) ||
        !tls13_write_cert(&child, x) ||
        !CBB_flush(cbb)) {
      return 0;
    }

    for (i = 0; i < sk_X509_num(chain); i++) {
      x = sk_X509_value(chain, i);
      if (!CBB_add_u24_length_prefixed(cbb, &child) ||
          !tls13_write_cert(&child, x) ||
          !CBB_flush(cbb)) {
        return 0;
      }
    }
  } else {
    X509_STORE_CTX xs_ctx;

    if (!X509_STORE_CTX_init(&xs_ctx, ssl->ctx->cert_store, x, NULL)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_X509_LIB);
      return 0;
    }
    X509_verify_cert(&xs_ctx);
    /* Don't leave errors in the queue */
    ERR_clear_error();
    for (i = 0; i < sk_X509_num(xs_ctx.chain); i++) {
      x = sk_X509_value(xs_ctx.chain, i);

      if (!CBB_add_u24_length_prefixed(cbb, &child) ||
          !tls13_write_cert(&child, x) ||
          !CBB_flush(cbb)) {
        X509_STORE_CTX_cleanup(&xs_ctx);
        return 0;
      }
    }
    X509_STORE_CTX_cleanup(&xs_ctx);
  }

  return 1;
}

int tls13_send_certificate(SSL *ssl, SSL_HS_MESSAGE *out) {
  CBB cbb;
  CBB_zero(&cbb);

  CBB context;
  CBB certificate_list;
  if (!CBB_init(&cbb, 0) ||
      !CBB_add_u8_length_prefixed(&cbb, &context) ||
      !CBB_add_bytes(&context, ssl->s3->hs->cert_context,
                     ssl->s3->hs->cert_context_len) ||
      !CBB_add_u24_length_prefixed(&cbb, &certificate_list) ||
      !tls13_write_server_cert_chain(ssl, &certificate_list)) {
    goto err;
  }

  uint8_t *data;
  size_t length;
  if (!CBB_finish(&cbb, &data, &length)) {
    goto err;
  }

  CBB_cleanup(&cbb);
  int ret = assemble_handshake_message(out, SSL3_MT_CERTIFICATE, data, length);
  OPENSSL_free(data);
  return ret;

err:
  CBB_cleanup(&cbb);
  return -1;
}

int tls13_send_certificate_verify(SSL *ssl, SSL_HS_MESSAGE *out) {
  CBB cbb;
  CBB_zero(&cbb);

  const EVP_MD *md = tls1_choose_signing_digest(ssl);
  if (!CBB_init(&cbb, 0) ||
      !tls12_add_sigandhash(ssl, &cbb, md)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  uint8_t digest[EVP_MAX_MD_SIZE];
  size_t digest_length;
  if (!tls13_cert_verify_digest(ssl, digest, &digest_length, ssl->server, md)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  printf("DIGEST: ");
  size_t i;
  for (i = 0; i < digest_length; i++) {
    printf("%02x", digest[i]);
  }
  printf("\n");

  /* Sign the digest. */
  CBB child;
  const size_t max_sig_len = ssl_private_key_max_signature_len(ssl);

  uint8_t *sig;
  size_t sig_len;
  if (!CBB_add_u16_length_prefixed(&cbb, &child) ||
      !CBB_reserve(&child, &sig, max_sig_len)) {
    goto err;
  }

  enum ssl_private_key_result_t sign_result = ssl_private_key_sign(
      ssl, sig, &sig_len, max_sig_len, md,
      digest, digest_length);
  switch (sign_result) {
    case ssl_private_key_success:
      break;
    case ssl_private_key_failure:
      goto err;
    case ssl_private_key_retry:
      ssl->rwstate = SSL_PRIVATE_KEY_OPERATION;
      goto err;
  }

  uint8_t *data;
  size_t length;
  if (!CBB_did_write(&child, sig_len) ||
      !CBB_finish(&cbb, &data, &length)) {
    goto err;
  }

  CBB_cleanup(&cbb);
  int ret = assemble_handshake_message(out, SSL3_MT_CERTIFICATE_VERIFY, data, length);
  OPENSSL_free(data);
  return ret;

err:
  CBB_cleanup(&cbb);
  return -1;
}

int tls13_send_finished(SSL *ssl, SSL_HS_MESSAGE *out) {
  printf("HELLO\n");
  size_t signature_len;
  uint8_t *signature = OPENSSL_malloc(EVP_MAX_MD_SIZE);

  if (!tls13_verify_finished(ssl, signature, &signature_len, ssl->server)) {
    goto f_err;
  }

  int ret = assemble_handshake_message(out, SSL3_MT_FINISHED, signature, signature_len);
  OPENSSL_free(signature);
  return ret;

f_err:
  OPENSSL_free(signature);
  ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
  OPENSSL_PUT_ERROR(SSL, SSL_R_DIGEST_CHECK_FAILED);
  return 0;
}

int tls13_finalize(SSL *ssl) {
  const EVP_MD *digest = ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl));
  SSL_HANDSHAKE *hs = ssl->s3->hs;

  if (hs->master_secret != NULL) {
    OPENSSL_free(hs->master_secret);
  }
  hs->master_secret = OPENSSL_malloc(EVP_MAX_MD_SIZE);

  if (!HKDF_extract(hs->master_secret, &hs->master_secret_len,
                    digest, NULL, 0,
                    hs->handshake_secret, hs->handshake_secret_len)) {
    return 0;
  }
  return update_traffic_secret(ssl, type_data);
}
