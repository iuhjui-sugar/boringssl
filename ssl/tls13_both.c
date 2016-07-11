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
    if (hs->handshake_interrupt & HS_NEED_WRITE) {
      int ret = tls13_handshake_write(ssl, hs->out_message);
      if (ret <= 0) {
        return ret;
      }
      hs->handshake_interrupt &= ~HS_NEED_WRITE;

      if (hs->handshake_interrupt & HS_NEED_FLUSH) {
        return 1;
      }
    }
    if (hs->handshake_interrupt & HS_NEED_HASH) {
      if (!tls13_store_handshake_context(ssl)) {
        return -1;
      }
      hs->handshake_interrupt &= ~HS_NEED_HASH;
    }
    if (hs->handshake_interrupt & HS_NEED_READ) {
      int ret = tls13_handshake_read(ssl, hs->in_message);
      if (ret <= 0) {
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

int tls13_assemble_handshake_message(SSL_HS_MESSAGE *out, uint8_t type,
                                     uint8_t *data, size_t length) {
  out->type = type;
  out->length = length;

  if (out->data != NULL) {
    OPENSSL_free(out->data);
    out->data = NULL;
  }
  out->data = OPENSSL_malloc(length);
  memcpy(out->data, data, length);

  if (out->raw != NULL) {
    OPENSSL_free(out->raw);
    out->raw = NULL;
  }
  out->offset = 0;

  return 1;
}

int tls13_handshake_read(SSL *ssl, SSL_HS_MESSAGE *msg) {
  int ok;
  long n = ssl->method->ssl_get_message(ssl, -1, ssl_hash_message, &ok);

  if (!ok) {
    return n;
  }

  msg->type = ssl->s3->tmp.message_type;
  msg->data = ssl->init_msg;
  msg->length = n;

  printf("IN: ");
  size_t i;
  for (i = 0; i < (size_t)n; i++) {
    printf("%02x", msg->data[i]);
  }
  printf("\n");

  return 1;
}

int tls13_handshake_write(SSL *ssl, SSL_HS_MESSAGE *msg) {
  if (!msg->offset) {
    CBB cbb, data;
    if (!ssl->method->init_message(ssl, &cbb, &data, msg->type) ||
        !CBB_add_bytes(&data, msg->data, msg->length) ||
        !ssl->method->finish_message(ssl, &cbb)) {
      return -1;
    }
    msg->offset = 1;
  }

  int ret = ssl->method->write_message(ssl);
  if (ret <= 0) {
    return ret;
  }

  printf("OUT (%d): ", msg->type);
  size_t i;
  for (i = 0; i < msg->length; i++) {
    printf("%02x", msg->data[i]);
  }
  printf("\n");

  msg->offset = 0;
  return 1;
}

static int tls13_fill_cert_verify_context(SSL *ssl, CBB *cbb, int server) {
  size_t pad;
  for (pad = 0; pad < 64; pad++) {
    if (!CBB_add_u8(cbb, 0x20)) {
      return 0;
    }
  }

  if (server) {
    const uint8_t kContext[] = "TLS 1.3, server CertificateVerify";
    if (!CBB_add_bytes(cbb, kContext, sizeof(kContext))) {
      return 0;
    }
  } else {
    const uint8_t kContext[] = "TLS 1.3, client CertificateVerify";
    if (!CBB_add_bytes(cbb, kContext, sizeof(kContext))) {
      return 0;
    }
  }

  if (!CBB_add_bytes(cbb, ssl->s3->hs->hash_context,
                     ssl->s3->hs->hash_context_len)) {
    return 0;
  }
  return 1;
}

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

  uint16_t signature_algorithm;
  if (!CBS_get_u16(&cbs, &signature_algorithm)) {
    al = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    goto f_err;
  }
  if (!tls12_check_peer_sigalg(ssl, &al, signature_algorithm, pkey)) {
    al = SSL_AD_ILLEGAL_PARAMETER;
    goto f_err;
  }

  CBS signature;
  if (!CBS_get_u16_length_prefixed(&cbs, &signature) ||
      CBS_len(&cbs) != 0) {
    al = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    goto f_err;
  }

  CBB hashed_data;
  if (!CBB_init(&hashed_data, 0) ||
      !tls13_fill_cert_verify_context(ssl, &hashed_data, !ssl->server)) {
    al = SSL_AD_INTERNAL_ERROR;
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    goto f_err;
  }

  int sig_ok = ssl_public_key_verify(
      ssl, CBS_data(&signature), CBS_len(&signature), signature_algorithm,
      pkey, CBB_data(&hashed_data), CBB_len(&hashed_data));

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
  EVP_PKEY_free(pkey);

  return ret;
}

int tls13_receive_finished(SSL *ssl, SSL_HS_MESSAGE msg) {
  size_t signature_len;
  uint8_t *signature = OPENSSL_malloc(EVP_MAX_MD_SIZE);

  if (!tls13_finished_mac(ssl, signature, &signature_len, !ssl->server)) {
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
  int ret = tls13_assemble_handshake_message(out, SSL3_MT_CERTIFICATE, data,
                                             length);
  OPENSSL_free(data);
  return ret;

err:
  CBB_cleanup(&cbb);
  return -1;
}

int tls13_send_certificate_verify(SSL *ssl, SSL_HS_MESSAGE *out) {
  CBB cbb;
  CBB_zero(&cbb);

  uint16_t signature_algorithm = tls1_choose_signature_algorithm(ssl);
  if (!CBB_init(&cbb, 0) ||
      !CBB_add_u16(&cbb, signature_algorithm)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  /* Sign the digest. */
  CBB child;
  const size_t max_sig_len = ssl_private_key_max_signature_len(ssl);

  uint8_t *sig;
  size_t sig_len;
  if (!CBB_add_u16_length_prefixed(&cbb, &child) ||
      !CBB_reserve(&child, &sig, max_sig_len)) {
    goto err;
  }

  CBB hashed_data;
  if (!CBB_init(&hashed_data, 0) ||
      !tls13_fill_cert_verify_context(ssl, &hashed_data, ssl->server)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  enum ssl_private_key_result_t sign_result = ssl_private_key_sign(
      ssl, sig, &sig_len, max_sig_len, signature_algorithm,
      CBB_data(&hashed_data), CBB_len(&hashed_data));

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
  int ret = tls13_assemble_handshake_message(out, SSL3_MT_CERTIFICATE_VERIFY, data,
                                             length);
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

  if (!tls13_finished_mac(ssl, signature, &signature_len, ssl->server)) {
    goto f_err;
  }

  int ret = tls13_assemble_handshake_message(out, SSL3_MT_FINISHED, signature,
                                             signature_len);
  OPENSSL_free(signature);
  return ret;

f_err:
  OPENSSL_free(signature);
  ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
  OPENSSL_PUT_ERROR(SSL, SSL_R_DIGEST_CHECK_FAILED);
  return 0;
}
