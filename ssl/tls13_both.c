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
#include <openssl/err.h>
#include <openssl/hkdf.h>
#include <openssl/mem.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "internal.h"


SSL_HANDSHAKE *ssl_handshake_new(int (*do_handshake)(SSL *ssl,
                                                     SSL_HANDSHAKE *hs)) {
  SSL_HANDSHAKE *hs = OPENSSL_malloc(sizeof(SSL_HANDSHAKE));
  if (hs == NULL) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  memset(hs, 0, sizeof(SSL_HANDSHAKE));
  hs->do_handshake = do_handshake;
  hs->handshake_state = HS_STATE_CLIENT_HELLO;
  return hs;
}

void ssl_handshake_free(SSL_HANDSHAKE *hs) {
  if (hs == NULL) {
    return;
  }

  OPENSSL_cleanse(hs->secret, sizeof(hs->secret));
  OPENSSL_cleanse(hs->traffic_secret_0, sizeof(hs->traffic_secret_0));
  if (hs->groups != NULL) {
    for (size_t i = 0; i < hs->groups_len; i++) {
      SSL_ECDH_CTX_cleanup(&hs->groups[i]);
    }
    OPENSSL_free(hs->groups);
  }
  OPENSSL_free(hs->kse_bytes);
  OPENSSL_free(hs->public_key);
  OPENSSL_free(hs->cert_context);
  OPENSSL_free(hs);
}

int tls13_handshake(SSL *ssl) {
  SSL_HANDSHAKE *hs = ssl->s3->hs;

  while (hs->handshake_state != HS_STATE_DONE) {
    if (hs->handshake_interrupt == hs_interrupt_write ||
        hs->handshake_interrupt == hs_interrupt_write_flight) {
      int ret = ssl->method->write_message(ssl);
      if (ret <= 0) {
        return ret;
      }
      if (hs->handshake_interrupt == hs_interrupt_write) {
        hs->handshake_interrupt = hs_interrupt_none;
      } else {
        hs->handshake_interrupt = hs_interrupt_flush;
      }
    }
    if (hs->handshake_interrupt == hs_interrupt_flush) {
      int ret = BIO_flush(ssl->wbio);
      if (ret <= 0) {
        ssl->rwstate = SSL_WRITING;
        return ret;
      }
      ssl->s3->hs->handshake_interrupt = hs_interrupt_none;
    }
    if (hs->handshake_interrupt == hs_interrupt_read) {
      int ret = ssl->method->ssl_get_message(ssl, -1, ssl_dont_hash_message);
      if (ret <= 0) {
        return ret;
      }
      hs->handshake_interrupt = hs_interrupt_none;
    }
    if (hs->handshake_interrupt == hs_interrupt_read_and_hash) {
      int ret = ssl->method->ssl_get_message(ssl, -1, ssl_hash_message);
      if (ret <= 0) {
        return ret;
      }
      hs->handshake_interrupt = hs_interrupt_none;
    }

    if (!hs->do_handshake(ssl, hs)) {
      return 0;
    }

    if (hs->handshake_interrupt == hs_interrupt_cb) {
      return -1;
    }
  }

  return 1;
}

static int tls13_get_cert_verify_signature_input(SSL *ssl, uint8_t **out,
                                                 size_t *out_len, int server) {
  CBB cbb;
  if (!CBB_init(&cbb, 64 + 33 + 1 + 2 * EVP_MAX_MD_SIZE)) {
    goto err;
  }

  for (size_t i = 0; i < 64; i++) {
    if (!CBB_add_u8(&cbb, 0x20)) {
      goto err;
    }
  }

  if (server) {
    /* Include the NUL byte. */
    static const char kContext[] = "TLS 1.3, server CertificateVerify";
    if (!CBB_add_bytes(&cbb, (const uint8_t *)kContext, sizeof(kContext))) {
      goto err;
    }
  } else {
    static const char kContext[] = "TLS 1.3, client CertificateVerify";
    if (!CBB_add_bytes(&cbb, (const uint8_t *)kContext, sizeof(kContext))) {
      goto err;
    }
  }

  uint8_t context_hashes[2 * EVP_MAX_MD_SIZE];
  size_t context_hashes_len;
  if (!tls13_get_context_hashes(ssl, context_hashes, &context_hashes_len) ||
      !CBB_add_bytes(&cbb, context_hashes, context_hashes_len) ||
      !CBB_finish(&cbb, out, out_len)) {
    goto err;
  }

  return 1;

err:
  OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
  CBB_cleanup(&cbb);
  return 0;
}

int tls13_receive_certificate(SSL *ssl) {
  CBS cbs;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);

  CBS context;
  if (!CBS_get_u8_length_prefixed(&cbs, &context) ||
      CBS_len(&context) != 0) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    return 0;
  }

  uint8_t alert;
  STACK_OF(X509) *chain = ssl_parse_cert_chain(
      ssl, &alert,
      ssl->ctx->retain_only_sha256_of_client_certs ? ssl->session->peer_sha256
                                                   : NULL,
      &cbs);
  if (chain == NULL) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
    goto err;
  }

  if (CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    goto err;
  }

  if (!ssl->server) {
    if (sk_X509_num(chain) == 0) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
      goto err;
    }

    X509 *leaf = sk_X509_value(chain, 0);
    if (!ssl_check_leaf_certificate(ssl, leaf)) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
      goto err;
    }

    /* NOTE: Unlike the server half, the client's copy of |cert_chain| includes
     * the leaf. */
    sk_X509_pop_free(ssl->session->cert_chain, X509_free);
    ssl->session->cert_chain = chain;
    chain = NULL;

    X509_free(ssl->session->peer);
    ssl->session->peer = X509_up_ref(leaf);

    ssl->session->verify_result = ssl->verify_result;

    int ret = ssl_verify_cert_chain(ssl, ssl->session->cert_chain);
    if (ssl->verify_mode != SSL_VERIFY_NONE && ret <= 0) {
      int al = ssl_verify_alarm_type(ssl->verify_result);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, al);
      OPENSSL_PUT_ERROR(SSL, SSL_R_CERTIFICATE_VERIFY_FAILED);
      goto err;
    } else {
      ERR_clear_error(); /* but we keep ssl->verify_result */
    }
  } else {
    if (sk_X509_num(chain) == 0) {
      /* TLS does not mind 0 certs returned */
      if ((ssl->verify_mode & SSL_VERIFY_PEER) &&
          (ssl->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)) {
        /* Fail for TLS only if we required a certificate */
        OPENSSL_PUT_ERROR(SSL, SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
        goto err;
      }
    } else {
      /* The hash would have been filled in. */
      if (ssl->ctx->retain_only_sha256_of_client_certs) {
        ssl->session->peer_sha256_valid = 1;
      }

      if (ssl_verify_cert_chain(ssl, chain) <= 0) {
        OPENSSL_PUT_ERROR(SSL, SSL_R_CERTIFICATE_VERIFY_FAILED);
        ssl3_send_alert(ssl, SSL3_AL_FATAL,
                        ssl_verify_alarm_type(ssl->verify_result));
        goto err;
      }
    }

    X509_free(ssl->session->peer);
    ssl->session->peer = sk_X509_shift(chain);
    ssl->session->verify_result = ssl->verify_result;

    sk_X509_pop_free(ssl->session->cert_chain, X509_free);
    ssl->session->cert_chain = chain;
    chain = NULL;
  }


  return 1;

err:
  sk_X509_pop_free(chain, X509_free);
  return 0;
}

int tls13_receive_certificate_verify(SSL *ssl) {
  int al, ret = 0;
  X509 *peer = ssl->session->peer;
  EVP_PKEY *pkey = NULL;
  uint8_t *msg = NULL;
  size_t msg_len;

  CBS cbs;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);

  /* Filter out unsupported certificate types. */
  pkey = X509_get_pubkey(peer);
  if (pkey == NULL) {
    goto err;
  }

  uint16_t signature_algorithm;
  if (!CBS_get_u16(&cbs, &signature_algorithm)) {
    al = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    goto f_err;
  }
  if (!tls12_check_peer_sigalg(ssl, &al, signature_algorithm)) {
    al = SSL_AD_ILLEGAL_PARAMETER;
    goto f_err;
  }
  ssl->s3->tmp.peer_signature_algorithm = signature_algorithm;

  CBS signature;
  if (!CBS_get_u16_length_prefixed(&cbs, &signature) ||
      CBS_len(&cbs) != 0) {
    al = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    goto f_err;
  }

  if (!tls13_get_cert_verify_signature_input(ssl, &msg, &msg_len,
                                             !ssl->server)) {
    al = SSL_AD_INTERNAL_ERROR;
    goto f_err;
  }

  int sig_ok =
      ssl_public_key_verify(ssl, CBS_data(&signature), CBS_len(&signature),
                            signature_algorithm, pkey, msg, msg_len);
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
  OPENSSL_free(msg);
  return ret;
}

int tls13_receive_finished(SSL *ssl) {
  uint8_t verify_data[EVP_MAX_MD_SIZE];
  size_t verify_data_len;
  if (!tls13_finished_mac(ssl, verify_data, &verify_data_len, !ssl->server)) {
    return 0;
  }

  if (ssl->init_num != verify_data_len ||
      CRYPTO_memcmp(verify_data, ssl->init_msg, verify_data_len) != 0) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECRYPT_ERROR);
    OPENSSL_PUT_ERROR(SSL, SSL_R_DIGEST_CHECK_FAILED);
    return 0;
  }

  return 1;
}

int tls13_send_certificate(SSL *ssl) {
  if (!ssl->server) {
    /* Call cert_cb to update the certificate. */
    if (!ssl->s3->hs->cert_cb && ssl->cert->cert_cb) {
      int rv = ssl->cert->cert_cb(ssl, ssl->cert->cert_cb_arg);
      if (rv == 0) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
        OPENSSL_PUT_ERROR(SSL, SSL_R_CERT_CB_ERROR);
        return 0;
      } else if (rv < 0) {
        ssl->rwstate = SSL_X509_LOOKUP;
        ssl->s3->hs->handshake_interrupt = hs_interrupt_cb;
        return 0;
      } else {
        ssl->s3->hs->handshake_interrupt = hs_interrupt_none;
      }

      ssl->s3->hs->cert_cb = 1;
    }

    if (!ssl_has_certificate(ssl) &&
        ssl->ctx->client_cert_cb != NULL) {
      /* Call client_cert_cb to update the certificate. */
      X509 *x509 = NULL;
      EVP_PKEY *pkey = NULL;

      int rv = ssl->ctx->client_cert_cb(ssl, &x509, &pkey);
      if (rv < 0) {
        ssl->rwstate = SSL_X509_LOOKUP;
        ssl->s3->hs->handshake_interrupt = hs_interrupt_cb;
        return 0;
      } else {
        ssl->s3->hs->handshake_interrupt = hs_interrupt_none;
      }

      int setup_error = rv == 1 && (!SSL_use_certificate(ssl, x509) ||
                                    !SSL_use_PrivateKey(ssl, pkey));
      X509_free(x509);
      EVP_PKEY_free(pkey);
      if (setup_error) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
        return 0;
      }
    }

    if (!ssl_has_certificate(ssl)) {
      ssl->s3->tmp.cert_request = 0;
    }

    ssl->s3->hs->cert_cb = 0;
  }

  CBB outer, cbb, context;
  if (!ssl->method->init_message(ssl, &outer, &cbb, SSL3_MT_CERTIFICATE) ||
      !CBB_add_u8_length_prefixed(&cbb, &context) ||
      !CBB_add_bytes(&context, ssl->s3->hs->cert_context,
                     ssl->s3->hs->cert_context_len) ||
      !ssl_add_cert_chain(ssl, &cbb) ||
      !ssl->method->finish_message(ssl, &outer)) {
    CBB_cleanup(&outer);
    return 0;
  }

  return 1;
}

int tls13_send_certificate_verify(SSL *ssl) {
  int ret = 0;
  uint8_t *msg = NULL;
  size_t msg_len;
  CBB outer, cbb;
  CBB_zero(&outer);

  uint16_t signature_algorithm;
  if (!tls1_choose_signature_algorithm(ssl, &signature_algorithm)) {
    goto err;
  }
  if (!ssl->method->init_message(ssl, &outer, &cbb, SSL3_MT_CERTIFICATE_VERIFY) ||
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

  enum ssl_private_key_result_t sign_result;
  if (ssl->s3->hs->handshake_interrupt == hs_interrupt_cb) {
    sign_result = ssl_private_key_complete(ssl, sig, &sig_len, max_sig_len);
  } else {
    if (!tls13_get_cert_verify_signature_input(ssl, &msg, &msg_len,
                                               ssl->server)) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
      goto err;
    }
    sign_result = ssl_private_key_sign(ssl, sig, &sig_len, max_sig_len,
                                       signature_algorithm, msg, msg_len);
  }

  switch (sign_result) {
    case ssl_private_key_success:
      ssl->s3->hs->handshake_interrupt = hs_interrupt_none;
      break;
    case ssl_private_key_failure:
      ssl->s3->hs->handshake_interrupt = hs_interrupt_error;
      goto err;
    case ssl_private_key_retry:
      ssl->rwstate = SSL_PRIVATE_KEY_OPERATION;
      ssl->s3->hs->handshake_interrupt = hs_interrupt_cb;
      goto err;
  }

  if (!CBB_did_write(&child, sig_len) ||
      !ssl->method->finish_message(ssl, &outer)) {
    goto err;
  }

  ret = 1;

err:
  CBB_cleanup(&outer);
  OPENSSL_free(msg);
  return ret;
}

int tls13_send_finished(SSL *ssl) {
  size_t signature_len;
  uint8_t signature[EVP_MAX_MD_SIZE];

  if (!tls13_finished_mac(ssl, signature, &signature_len, ssl->server)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
    OPENSSL_PUT_ERROR(SSL, SSL_R_DIGEST_CHECK_FAILED);
    return 0;
  }

  CBB outer, cbb;
  if (!ssl->method->init_message(ssl, &outer, &cbb, SSL3_MT_FINISHED) ||
      !CBB_add_bytes(&cbb, signature, signature_len) ||
      !ssl->method->finish_message(ssl, &outer)) {
    CBB_cleanup(&outer);
    return 0;
  }

  return 1;
}
