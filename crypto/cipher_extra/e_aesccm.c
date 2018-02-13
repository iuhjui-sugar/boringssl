/* ====================================================================
 * Copyright (c) 2001-2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ==================================================================== */

#include <openssl/aead.h>
#include <openssl/cipher.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "../fipsmodule/cipher/internal.h"

#define EVP_AEAD_AES_CCM_TAG_LEN 16
#define EVP_AEAD_AES_CCM_NONCE_LEN 14

struct aead_aes_ccm_ctx {
  union {
    double align;
    AES_KEY ks;
  } ks;
  ctr128_f ctr;
  block128_f block;
  CCM128_CONTEXT ccm;
};

static int aead_aes_ccm_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                             size_t key_len, size_t tag_len) {
  struct aead_aes_ccm_ctx *ccm_ctx;
  ccm_ctx = OPENSSL_malloc(sizeof(struct aead_aes_ccm_ctx));
  if (ccm_ctx == NULL) {
    OPENSSL_PUT_ERROR(CIPHER, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  if (key_len != 16) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_KEY_LENGTH);
    return 0;  // EVP_AEAD_CTX_init should catch this.
  }

  if (tag_len == EVP_AEAD_DEFAULT_TAG_LENGTH) {
    tag_len = EVP_AEAD_AES_CCM_TAG_LEN;
  }

  if (tag_len > EVP_AEAD_AES_CCM_TAG_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TAG_TOO_LARGE);
    return 0;
  }

  ccm_ctx->ctr =
      aes_ctr_set_key(&ccm_ctx->ks.ks, NULL, &ccm_ctx->block, key, key_len);
  ctx->tag_len = tag_len;
  CRYPTO_ccm128_init(&ccm_ctx->ccm, tag_len, &ccm_ctx->ks.ks, ccm_ctx->block);

  ctx->aead_state = ccm_ctx;

  return 1;
}

static void aead_aes_ccm_cleanup(EVP_AEAD_CTX *ctx) {
  OPENSSL_free(ctx->aead_state);
}

static int aead_aes_ccm_seal_scatter(const EVP_AEAD_CTX *ctx, uint8_t *out,
                                     uint8_t *out_tag, size_t *out_tag_len,
                                     size_t max_out_tag_len,
                                     const uint8_t *nonce, size_t nonce_len,
                                     const uint8_t *in, size_t in_len,
                                     const uint8_t *extra_in,
                                     size_t extra_in_len,
                                     const uint8_t *ad, size_t ad_len) {
  const struct aead_aes_ccm_ctx *ccm_ctx = ctx->aead_state;
  CCM128_CONTEXT ccm;

  if (in_len >> 24) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }
  if (max_out_tag_len < extra_in_len + ctx->tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }
  if (nonce_len > EVP_AEAD_AES_CCM_NONCE_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_NONCE_SIZE);
    return 0;
  }

  OPENSSL_memcpy(&ccm, &ccm_ctx->ccm, sizeof(ccm));

  if (!CRYPTO_ccm128_setiv(&ccm, &ccm_ctx->ks.ks, nonce, nonce_len, in_len)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_NONCE_SIZE);
    return 0;
  }

  if (ad_len > 0 && !CRYPTO_ccm128_aad(&ccm, &ccm_ctx->ks.ks, ad, ad_len)) {
    return 0;
  }

  if (!CRYPTO_ccm128_encrypt(&ccm, &ccm_ctx->ks.ks, in, out, in_len)) {
    return 0;
  }

  CRYPTO_ccm128_tag(&ccm, out_tag, ctx->tag_len);
  *out_tag_len = ctx->tag_len;

  return 1;
}

static int aead_aes_ccm_open_gather(const EVP_AEAD_CTX *ctx, uint8_t *out,
                                    const uint8_t *nonce, size_t nonce_len,
                                    const uint8_t *in, size_t in_len,
                                    const uint8_t *in_tag, size_t in_tag_len,
                                    const uint8_t *ad, size_t ad_len) {
  const struct aead_aes_ccm_ctx *ccm_ctx = ctx->aead_state;
  uint8_t tag[EVP_AEAD_AES_CCM_TAG_LEN];
  CCM128_CONTEXT ccm;

  if (nonce_len > EVP_AEAD_AES_CCM_NONCE_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_NONCE_SIZE);
    return 0;
  }

  if (in_tag_len != ctx->tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  OPENSSL_memcpy(&ccm, &ccm_ctx->ccm, sizeof(ccm));

  if (!CRYPTO_ccm128_setiv(&ccm, &ccm_ctx->ks.ks, nonce, nonce_len, in_len)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_NONCE_SIZE);
    return 0;
  }

  if (ad_len > 0 && !CRYPTO_ccm128_aad(&ccm, &ccm_ctx->ks.ks, ad, ad_len)) {
    return 0;
  }

  if (!CRYPTO_ccm128_decrypt(&ccm, &ccm_ctx->ks.ks, in, out, in_len)) {
    return 0;
  }

  CRYPTO_ccm128_tag(&ccm, tag, ctx->tag_len);
  if (CRYPTO_memcmp(tag, in_tag, ctx->tag_len) != 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  return 1;
}

static const EVP_AEAD aead_aes_128_ccm = {
  16,
  EVP_AEAD_AES_CCM_NONCE_LEN, // nonce length
  EVP_AEAD_AES_CCM_TAG_LEN,   // overhead
  EVP_AEAD_AES_CCM_TAG_LEN,   // max tag length
  0,                          // seal_scatter_supports_extra_in

  aead_aes_ccm_init,
  NULL /* init_with_direction */,
  aead_aes_ccm_cleanup,
  NULL /* open */,
  aead_aes_ccm_seal_scatter,
  aead_aes_ccm_open_gather,
  NULL /* get_iv */,
  NULL /* tag_len */,
};

const EVP_AEAD *EVP_aead_aes_128_ccm(void) {
  return &aead_aes_128_ccm;
}
