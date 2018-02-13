/* Copyright (c) 2018, Google Inc.
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

#include <openssl/aead.h>
#include <openssl/cipher.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "../fipsmodule/cipher/internal.h"


#define EVP_AEAD_AES_CCM_TAG_LEN 4
#define EVP_AEAD_AES_CCM_NONCE_LEN 13

struct aead_aes_ccm_ctx {
  union {
    double align;
    AES_KEY ks;
  } ks;
  ctr128_f ctr;
  block128_f block;
  unsigned M;
  unsigned L;
  size_t max_plain;
};

static int aead_aes_ccm_bluetooth_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                       size_t key_len, size_t tag_len) {
  struct aead_aes_ccm_ctx *ccm_ctx =
      OPENSSL_malloc(sizeof(struct aead_aes_ccm_ctx));
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

  if (tag_len != EVP_AEAD_AES_CCM_TAG_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TAG_TOO_LARGE);
    return 0;
  }

  ccm_ctx->ctr =
      aes_ctr_set_key(&ccm_ctx->ks.ks, NULL, &ccm_ctx->block, key, key_len);
  ctx->tag_len = tag_len;
  ccm_ctx->M = tag_len;
  ccm_ctx->L = 15 - EVP_AEAD_AES_CCM_NONCE_LEN;
  ccm_ctx->max_plain = 1 << 16;

  ctx->aead_state = ccm_ctx;

  return 1;
}

static void aead_aes_ccm_cleanup(EVP_AEAD_CTX *ctx) {
  OPENSSL_free(ctx->aead_state);
}

static int aead_aes_ccm_seal_scatter(
    const EVP_AEAD_CTX *ctx, uint8_t *out, uint8_t *out_tag,
    size_t *out_tag_len, size_t max_out_tag_len, const uint8_t *nonce,
    size_t nonce_len, const uint8_t *in, size_t in_len, const uint8_t *extra_in,
    size_t extra_in_len, const uint8_t *ad, size_t ad_len) {
  const struct aead_aes_ccm_ctx *ccm_ctx = ctx->aead_state;

  if (in_len > ccm_ctx->max_plain) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (max_out_tag_len < ctx->tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (nonce_len != EVP_AEAD_AES_CCM_NONCE_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_NONCE_SIZE);
    return 0;
  }

  CCM128_CONTEXT ccm;
  if (!CRYPTO_ccm128_init(&ccm, ccm_ctx->M, ccm_ctx->L, &ccm_ctx->ks.ks,
                          ccm_ctx->block, nonce, nonce_len, ad, ad_len,
                          in_len) ||
      !CRYPTO_ccm128_encrypt(&ccm, &ccm_ctx->ks.ks, in, out, in_len)) {
    OPENSSL_PUT_ERROR(CIPHER, ERR_R_INTERNAL_ERROR);
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

  if (in_len > ccm_ctx->max_plain) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (nonce_len != EVP_AEAD_AES_CCM_NONCE_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_NONCE_SIZE);
    return 0;
  }

  if (in_tag_len != ctx->tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  CCM128_CONTEXT ccm;
  if (!CRYPTO_ccm128_init(&ccm, ccm_ctx->M, ccm_ctx->L, &ccm_ctx->ks.ks,
                          ccm_ctx->block, nonce, nonce_len, ad, ad_len,
                          in_len) ||
      !CRYPTO_ccm128_decrypt(&ccm, &ccm_ctx->ks.ks, in, out, in_len)) {
    OPENSSL_PUT_ERROR(CIPHER, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  CRYPTO_ccm128_tag(&ccm, tag, ctx->tag_len);
  if (CRYPTO_memcmp(tag, in_tag, ctx->tag_len) != 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  return 1;
}

static const EVP_AEAD aead_aes_128_ccm_bluetooth = {
    16,
    EVP_AEAD_AES_CCM_NONCE_LEN,  // nonce length
    EVP_AEAD_AES_CCM_TAG_LEN,    // overhead
    EVP_AEAD_AES_CCM_TAG_LEN,    // max tag length
    0,                           // seal_scatter_supports_extra_in

    aead_aes_ccm_bluetooth_init,
    NULL /* init_with_direction */,
    aead_aes_ccm_cleanup,
    NULL /* open */,
    aead_aes_ccm_seal_scatter,
    aead_aes_ccm_open_gather,
    NULL /* get_iv */,
    NULL /* tag_len */,
};

const EVP_AEAD *EVP_aead_aes_128_ccm_bluetooth(void) {
  return &aead_aes_128_ccm_bluetooth;
}
