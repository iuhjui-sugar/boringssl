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

static int tls13_store_handshake_context(SSL *ssl);

static int tls13_send_client_hello(SSL *ssl, SSL_HS_MESSAGE *out) {
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

  CBB_cleanup(&cbb);
  int ret = assemble_handshake_message(out, SSL3_MT_CLIENT_HELLO, data, length);
  OPENSSL_free(data);
  return ret;

err:
  CBB_cleanup(&cbb);
  return -1;
}

static int tls13_receive_server_hello(SSL *ssl, SSL_HS_MESSAGE msg) {
  int alert;

  CBS cbs;
  CBS_init(&cbs, msg.data, msg.length);

  CBS server_random;
  uint16_t cipher_suite;
  if (!CBS_get_u16(&cbs, (uint16_t*)&ssl->version) ||
      !CBS_get_bytes(&cbs, &server_random, SSL3_RANDOM_SIZE) ||
      !CBS_get_u16(&cbs, &cipher_suite)) {
    alert = SSL_AD_DECODE_ERROR;
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

  return 1;

fatal_err:
  ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
err:
  return -1;
}

static int tls13_receive_encrypted_extensions(SSL *ssl, SSL_HS_MESSAGE msg) {
  int alert;

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
  return -1;
}

static int ca_dn_cmp(const X509_NAME **a, const X509_NAME **b) {
  return X509_NAME_cmp(*a, *b);
}

static int tls13_receive_certificate_request(SSL *ssl, SSL_HS_MESSAGE msg) {
  int ret = 0;
  X509_NAME *xn = NULL;
  STACK_OF(X509_NAME) *ca_sk = NULL;

  ssl->s3->tmp.cert_req = 0;

  CBS cbs;
  CBS_init(&cbs, msg.data, msg.length);

  ca_sk = sk_X509_NAME_new(ca_dn_cmp);
  if (ca_sk == NULL) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  CBS context, supported_signature_algorithms;
  if (!CBS_get_u8_length_prefixed(&cbs, &context) ||
      !CBS_stow(&context, &ssl->hs->cert_context, &ssl->hs->cert_context_len) ||
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

static int tls13_receive_certificate(SSL *ssl, SSL_HS_MESSAGE msg) {
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

static int tls13_receive_certificate_verify(SSL *ssl, SSL_HS_MESSAGE msg) {
  int al, ret = 0;
  X509 *peer = ssl->session->peer;
  EVP_PKEY *pkey = NULL;
  const EVP_MD *md = NULL;
  uint8_t digest[EVP_MAX_MD_SIZE];
  size_t digest_length;
  EVP_MD_CTX mctx;
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

  CBB hashed_data;
  const uint8_t kServerContext[] = "TLS 1.3, server CertificateVerify";
  if (!CBB_init(&hashed_data, 64 + sizeof(kServerContext) + ssl->hs->hs_context_len)) {
    goto err;
  }

  size_t pad;
  for (pad = 0; pad < 64; pad++) {
    if (!CBB_add_u8(&hashed_data, 0x20)) {
      goto err;
    }
  }
  if (!CBB_add_bytes(&hashed_data, kServerContext, sizeof(kServerContext)) ||
      !CBB_add_bytes(&hashed_data, ssl->hs->hs_context,
                     ssl->hs->hs_context_len)) {
    goto err;
  }

  unsigned len;
  EVP_MD_CTX_init(&mctx);
  if (!EVP_DigestInit_ex(&mctx, md, NULL) ||
      !EVP_DigestUpdate(&mctx, CBB_data(&hashed_data), CBB_len(&hashed_data)) ||
      !EVP_DigestFinal(&mctx, digest, &len)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_EVP_LIB);
    goto err;
  }
  digest_length = len;

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


  if (!tls13_update_master_secret(ssl)) {
    goto err;
  }
  ret = 1;

  if (0) {
  f_err:
    ssl3_send_alert(ssl, SSL3_AL_FATAL, al);
  }

err:
  EVP_MD_CTX_cleanup(&mctx);
  EVP_PKEY_CTX_free(pctx);
  EVP_PKEY_free(pkey);

  return ret;
}

static int tls13_receive_finished(SSL *ssl, SSL_HS_MESSAGE msg) {
  size_t signature_len;
  uint8_t *signature = OPENSSL_malloc(EVP_MAX_MD_SIZE);

  if (!tls13_verify_finished(signature, &signature_len, ssl, 1)) {
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

static int tls13_send_certificate(SSL *ssl, SSL_HS_MESSAGE *out) {
  // TODO(IMPLEMENT)
  return 1;
}

static int tls13_send_certificate_verify(SSL *ssl, SSL_HS_MESSAGE *out) {
  // TODO(IMPLEMENT)
  return 1;
}

static int tls13_send_finished(SSL *ssl, SSL_HS_MESSAGE *out) {
  size_t signature_len;
  uint8_t *signature = OPENSSL_malloc(EVP_MAX_MD_SIZE);

  if (!tls13_verify_finished(signature, &signature_len, ssl, 0)) {
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

static int tls13_finalize(SSL *ssl) {
  if (!tls13_update_traffic_keys(ssl, tls13_type_data,
                                 ssl->hs->traffic_secret, ssl->hs->key_len,
                                 ssl->hs->hs_context, ssl->hs->hs_context_len)) {
    return 0;
  }

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

static int tls13_store_handshake_context(SSL *ssl) {
  EVP_MD_CTX hh;
  EVP_MD_CTX_init(&hh);
  if (!EVP_MD_CTX_copy_ex(&hh, &ssl->s3->handshake_hash)) {
    EVP_MD_CTX_cleanup(&hh);
    return 0;
  }

  if (ssl->hs->hs_context) {
    OPENSSL_free(ssl->hs->hs_context);
  }

  ssl->hs->hs_context = OPENSSL_malloc(EVP_MD_size(hh.digest));
  if (!EVP_DigestFinal_ex(&hh, ssl->hs->hs_context,
                          &ssl->hs->hs_context_len)) {
    EVP_MD_CTX_cleanup(&hh);
    return 0;
  }

  EVP_MD_CTX_cleanup(&hh);
  return 1;
}

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
    case HS_STATE_CLIENT_HELLO:
      result = tls13_send_client_hello(ssl, ssl->hs->out_message);
      ssl->hs->handshake_state = HS_STATE_SERVER_HELLO;
      ssl->hs->handshake_interrupt = HS_NEED_WRITE_FLIGHT | HS_NEED_READ;
      break;
    case HS_STATE_SERVER_HELLO:
      if (ssl->hs->in_message->type == SSL3_MT_HELLO_RETRY_REQUEST) {
        // TODO: Handle HelloRetryRequest
        result = 0;
        ssl->hs->handshake_state = HS_STATE_CLIENT_HELLO;
        ssl->hs->handshake_interrupt = HS_NEED_NONE;
        break;
      }
      if (ssl->hs->in_message->type != SSL3_MT_SERVER_HELLO) {
        result = 0;
        break;
      }
      result = tls13_receive_server_hello(ssl, *ssl->hs->in_message);
      ssl->hs->handshake_state = HS_STATE_SERVER_ENCRYPTED_EXTENSIONS;
      ssl->hs->handshake_interrupt = HS_NEED_READ;
      break;
    case HS_STATE_SERVER_ENCRYPTED_EXTENSIONS:
      if (ssl->hs->in_message->type != SSL3_MT_ENCRYPTED_EXTENSIONS) {
        result = 0;
        break;
      }
      result = tls13_receive_encrypted_extensions(ssl, *ssl->hs->in_message);
      if (ssl->hs->cipher->algorithm_auth & SSL_aPSK) {
        if (!tls13_store_handshake_context(ssl)) {
          result = -1;
          break;
        }
        ssl->hs->handshake_state = HS_STATE_SERVER_FINISHED;
      } else {
        ssl->hs->handshake_state = HS_STATE_SERVER_CERTIFICATE_REQUEST;
      }
      ssl->hs->handshake_interrupt = HS_NEED_READ;
      break;
    case HS_STATE_SERVER_CERTIFICATE_REQUEST:
      if (!tls13_store_handshake_context(ssl)) {
        result = -1;
        break;
      }
      if (ssl->hs->in_message->type == SSL3_MT_CERTIFICATE_REQUEST) {
        result = tls13_receive_certificate_request(ssl, *ssl->hs->in_message);
        ssl->hs->handshake_interrupt = HS_NEED_READ;
      } else {
        result = 1;
        ssl->hs->handshake_interrupt = HS_NEED_NONE;
      }
      ssl->hs->handshake_state = HS_STATE_SERVER_CERTIFICATE;
      break;
    case HS_STATE_SERVER_CERTIFICATE:
      if (ssl->hs->in_message->type != SSL3_MT_CERTIFICATE) {
        result = 0;
        break;
      }
      result = tls13_receive_certificate(ssl, *ssl->hs->in_message);
      ssl->hs->handshake_state = HS_STATE_SERVER_CERTIFICATE_VERIFY;
      ssl->hs->handshake_interrupt = HS_NEED_READ;
      break;
    case HS_STATE_SERVER_CERTIFICATE_VERIFY:
      if (ssl->hs->in_message->type != SSL3_MT_CERTIFICATE_VERIFY) {
        result = 0;
        break;
      }
      result = tls13_receive_certificate_verify(ssl, *ssl->hs->in_message);
      if (!tls13_store_handshake_context(ssl)) {
        result = -1;
        break;
      }
      ssl->hs->handshake_state = HS_STATE_SERVER_FINISHED;
      ssl->hs->handshake_interrupt = HS_NEED_READ;
      break;
    case HS_STATE_SERVER_FINISHED:
      if (ssl->hs->in_message->type != SSL3_MT_FINISHED) {
        result = 0;
        break;
      }
      result = tls13_receive_finished(ssl, *ssl->hs->in_message);
      if (!ssl->hs->cert_context) {
        if (!tls13_store_handshake_context(ssl)) {
          result = -1;
          break;
        }
        ssl->hs->handshake_state = HS_STATE_CLIENT_FINISHED;
      } else {
        ssl->hs->handshake_state = HS_STATE_CLIENT_CERTIFICATE;
      }
      ssl->hs->handshake_interrupt = HS_NEED_NONE;
      break;
    case HS_STATE_CLIENT_CERTIFICATE:
      result = tls13_send_certificate(ssl, ssl->hs->out_message);
      ssl->hs->handshake_state = HS_STATE_CLIENT_CERTIFICATE_VERIFY;
      ssl->hs->handshake_interrupt = HS_NEED_WRITE;
      break;
    case HS_STATE_CLIENT_CERTIFICATE_VERIFY:
      result = tls13_send_certificate_verify(ssl, ssl->hs->out_message);
      if (!tls13_store_handshake_context(ssl)) {
        result = -1;
        break;
      }
      ssl->hs->handshake_state = HS_STATE_CLIENT_FINISHED;
      ssl->hs->handshake_interrupt = HS_NEED_WRITE;
      break;
    case HS_STATE_CLIENT_FINISHED:
      result = tls13_send_finished(ssl, ssl->hs->out_message);
      ssl->hs->handshake_state = HS_STATE_FINISH;
      ssl->hs->handshake_interrupt = HS_NEED_WRITE_FLIGHT;
      break;
    case HS_STATE_FINISH:
      if (!tls13_finalize(ssl)) {
        result = -1;
        break;
      }
      ssl->hs->handshake_state = HS_STATE_DONE;
      ssl->hs->handshake_interrupt = HS_NEED_NONE;
    default:
      break;
  }

  if (cb != NULL) {
    cb(ssl, SSL_CB_CONNECT_LOOP, result);
  }
  return result;
}

static int tls13_receive_session_ticket(SSL *ssl, SSL_HS_MESSAGE msg) {
  int alert;

  CBS cbs;
  CBS_init(&cbs, msg.data, msg.length);

  uint32_t lifetime;
  CBS ticket;
  if (!CBS_get_u32(&cbs, &lifetime) ||
      !CBS_get_u16_length_prefixed(&cbs, &ticket)) {
    alert = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    goto fatal_err;
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
  return -1;
}

int tls13_client_post_handshake(SSL *ssl, SSL_HS_MESSAGE msg) {
  switch (msg.type) {
    case SSL3_MT_NEW_SESSION_TICKET:
      return tls13_receive_session_ticket(ssl, msg);
    default:
      return 0;
  }
}
