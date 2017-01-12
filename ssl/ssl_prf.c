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
#include <limits.h>
#include <string.h>

#include <openssl/buf.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/md5.h>
#include <openssl/nid.h>
#include <openssl/sha.h>

#include "../crypto/internal.h"
#include "internal.h"

int SSL_PRF_init(SSL_PRF *prf, int algorithm_prf) {
  prf->algorithm = algorithm_prf;

  switch (prf->algorithm) {
    case SSL_HANDSHAKE_MAC_DEFAULT:
      prf->md = EVP_sha1();
      break;
    case SSL_HANDSHAKE_MAC_SHA256:
      prf->md = EVP_sha256();
      break;
    case SSL_HANDSHAKE_MAC_SHA384:
      prf->md = EVP_sha384();
      break;
    default:
      return 0;
  }

  EVP_MD_CTX_init(&prf->hs_hash);
  EVP_MD_CTX_init(&prf->hs_md5);

  return 1;
}

/* init_digest_with_data calls |EVP_DigestInit_ex| on |ctx| with |md| and then
 * writes the data in |buf| to it. */
static int init_digest_with_data(EVP_MD_CTX *ctx, const EVP_MD *md,
                                 const BUF_MEM *buf) {
  if (!EVP_DigestInit_ex(ctx, md, NULL)) {
    return 0;
  }
  EVP_DigestUpdate(ctx, buf->data, buf->length);
  return 1;
}

int SSL_PRF_init_hash(SSL_PRF *prf) {
  SSL_PRF_free_hash(prf);

  EVP_MD_CTX_init(&prf->hs_hash);
  EVP_MD_CTX_init(&prf->hs_md5);

  if (!init_digest_with_data(&prf->hs_hash, prf->md, prf->hs_buffer)) {
    return 0;
  }

  if (prf->algorithm == SSL_HANDSHAKE_MAC_DEFAULT &&
      !init_digest_with_data(&prf->hs_md5, EVP_md5(), prf->hs_buffer)) {
    return 0;
  }

  return 1;
}

void SSL_PRF_free_hash(SSL_PRF *prf) {
  EVP_MD_CTX_cleanup(&prf->hs_hash);
  EVP_MD_CTX_cleanup(&prf->hs_md5);
}

int SSL_PRF_init_transcript(SSL_PRF *prf) {
  SSL_PRF_free_transcript(prf);
  SSL_PRF_free_hash(prf);

  prf->hs_buffer = BUF_MEM_new();
  return prf->hs_buffer != NULL;
}

void SSL_PRF_free_transcript(SSL_PRF *prf) {
  BUF_MEM_free(prf->hs_buffer);
  prf->hs_buffer = NULL;
}

int SSL_PRF_update_handshake(SSL_PRF *prf, const uint8_t *in, size_t in_len) {
  /* Depending on the state of the handshake, either the handshake buffer may be
   * active, the rolling hash, or both. */
  if (prf->hs_buffer != NULL) {
    size_t new_len = prf->hs_buffer->length + in_len;
    if (new_len < in_len) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_OVERFLOW);
      return 0;
    }
    if (!BUF_MEM_grow(prf->hs_buffer, new_len)) {
      return 0;
    }
    OPENSSL_memcpy(prf->hs_buffer->data + new_len - in_len, in, in_len);
  }

  if (EVP_MD_CTX_md(&prf->hs_hash) != NULL) {
    EVP_DigestUpdate(&prf->hs_hash, in, in_len);
  }
  if (prf->algorithm == SSL_HANDSHAKE_MAC_DEFAULT &&
      EVP_MD_CTX_md(&prf->hs_md5) != NULL) {
    EVP_DigestUpdate(&prf->hs_md5, in, in_len);
  }

  return 1;
}

static int ssl3_handshake_mac(SSL_PRF *prf, SSL_SESSION *session, int md_nid,
                              const char *sender, size_t sender_len,
                              uint8_t *p) {
  unsigned int ret;
  size_t npad, n;
  unsigned int i;
  uint8_t md_buf[EVP_MAX_MD_SIZE];
  EVP_MD_CTX ctx;
  const EVP_MD_CTX *ctx_template;

  if (md_nid == NID_md5) {
    ctx_template = &prf->hs_md5;
  } else if (md_nid == EVP_MD_CTX_type(&prf->hs_hash)) {
    ctx_template = &prf->hs_hash;
  } else {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_REQUIRED_DIGEST);
    return 0;
  }

  EVP_MD_CTX_init(&ctx);
  if (!EVP_MD_CTX_copy_ex(&ctx, ctx_template)) {
    EVP_MD_CTX_cleanup(&ctx);
    OPENSSL_PUT_ERROR(SSL, ERR_LIB_EVP);
    return 0;
  }

  static const uint8_t kPad1[48] = {
      0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
      0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
      0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
      0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
  };

  static const uint8_t kPad2[48] = {
      0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
      0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
      0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
      0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
  };

  n = EVP_MD_CTX_size(&ctx);

  npad = (48 / n) * n;
  if (sender != NULL) {
    EVP_DigestUpdate(&ctx, sender, sender_len);
  }
  EVP_DigestUpdate(&ctx, session->master_key, session->master_key_length);
  EVP_DigestUpdate(&ctx, kPad1, npad);
  EVP_DigestFinal_ex(&ctx, md_buf, &i);

  if (!EVP_DigestInit_ex(&ctx, EVP_MD_CTX_md(&ctx), NULL)) {
    EVP_MD_CTX_cleanup(&ctx);
    OPENSSL_PUT_ERROR(SSL, ERR_LIB_EVP);
    return 0;
  }
  EVP_DigestUpdate(&ctx, session->master_key, session->master_key_length);
  EVP_DigestUpdate(&ctx, kPad2, npad);
  EVP_DigestUpdate(&ctx, md_buf, i);
  EVP_DigestFinal_ex(&ctx, p, &ret);

  EVP_MD_CTX_cleanup(&ctx);

  return ret;
}

int SSL_PRF_cert_verify_hash(SSL_PRF *prf, SSL_SESSION *session, uint8_t *out,
                             size_t *out_len, int signature_algorithm,
                             int version) {
  if (version != SSL3_VERSION) {
    return 0;
  }

  if (signature_algorithm == SSL_SIGN_RSA_PKCS1_MD5_SHA1) {
    if (ssl3_handshake_mac(prf, session, NID_md5, NULL, 0, out) == 0 ||
        ssl3_handshake_mac(prf, session, NID_sha1, NULL, 0, out + MD5_DIGEST_LENGTH) ==
        0) {
      return 0;
    }
    *out_len = MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH;
  } else if (signature_algorithm == SSL_SIGN_ECDSA_SHA1) {
    if (ssl3_handshake_mac(prf, session, NID_sha1, NULL, 0, out) == 0) {
      return 0;
    }
    *out_len = SHA_DIGEST_LENGTH;
  } else {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return 0;
  }
  return 1;
}

int SSL_PRF_finish_mac(SSL_PRF *prf, SSL_SESSION *session, uint8_t *out, int from_server,
                       int version) {
  if (version == SSL3_VERSION) {
    const char *sender = from_server ? SSL3_MD_SERVER_FINISHED_CONST
                                     : SSL3_MD_CLIENT_FINISHED_CONST;
    const size_t sender_len = 4;
    int ret, sha1len;
    ret = ssl3_handshake_mac(prf, session, NID_md5, sender, sender_len, out);
    if (ret == 0) {
      return 0;
    }

    out += ret;

    sha1len =
        ssl3_handshake_mac(prf, session, NID_sha1, sender, sender_len, out);
    if (sha1len == 0) {
      return 0;
    }

    ret += sha1len;
    return ret;
  }

  /* At this point, the handshake should have released the handshake buffer on
   * its own. */
  assert(prf->hs_buffer == NULL);

  const char *label = TLS_MD_CLIENT_FINISH_CONST;
  size_t label_len = TLS_MD_SERVER_FINISH_CONST_SIZE;
  if (from_server) {
    label = TLS_MD_SERVER_FINISH_CONST;
    label_len = TLS_MD_SERVER_FINISH_CONST_SIZE;
  }

  uint8_t buf[EVP_MAX_MD_SIZE];
  int digests_len = tls1_handshake_digest(prf, buf, sizeof(buf));
  if (digests_len < 0) {
    return 0;
  }

  static const size_t kFinishedLen = 12;
  if (!tls1_prf(prf, out, kFinishedLen, session->master_key,
                session->master_key_length, label, label_len, buf,
                digests_len, NULL, 0)) {
    return 0;
  }

  return (int)kFinishedLen;
}
