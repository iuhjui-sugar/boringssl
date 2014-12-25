/* ====================================================================
 * Copyright (c) 2012 The OpenSSL Project.  All rights reserved.
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
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */

#include <assert.h>
#include <limits.h>
#include <string.h>

#include <openssl/aead.h>
#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/sha.h>

#include "../crypto/internal.h"
#include "internal.h"


typedef struct {
  EVP_CIPHER_CTX cipher_ctx;
  HMAC_CTX hmac_ctx;
  /* mac_secret is the portion of the key used for the MAC. It is retained
   * separately for the constant-time CBC code. */
  uint8_t mac_key[EVP_MAX_MD_SIZE];
  size_t mac_key_len;
  /* ciph_secret is the portion of the key used for the stream or block
   * cipher. It is retained separately to allow the EVP_CIPHER_CTX to be
   * initialized once the direction is known. */
  uint8_t enc_key[EVP_MAX_KEY_LENGTH];
  size_t enc_key_len;
  /* iv is the portion of the key used for the fixed IV. It is retained
   * separately to allow the EVP_CIPHER_CTX to be initialized once the direction
   * is known. */
  uint8_t iv[EVP_MAX_IV_LENGTH];
  size_t iv_len;
  /* implicit_iv is one iff this is a pre-TLS-1.1 CBC cipher without an explicit
   * IV. */
  char implicit_iv;
  char initialized;
} AEAD_TLS_CTX;


static void aead_tls_cleanup(EVP_AEAD_CTX *ctx) {
  AEAD_TLS_CTX *tls_ctx = (AEAD_TLS_CTX *)ctx->aead_state;
  EVP_CIPHER_CTX_cleanup(&tls_ctx->cipher_ctx);
  HMAC_CTX_cleanup(&tls_ctx->hmac_ctx);
  OPENSSL_cleanse(&tls_ctx->mac_key, sizeof(tls_ctx->mac_key));
  OPENSSL_cleanse(&tls_ctx->enc_key, sizeof(tls_ctx->enc_key));
  OPENSSL_cleanse(&tls_ctx->iv, sizeof(tls_ctx->iv));
  OPENSSL_free(tls_ctx);
  ctx->aead_state = NULL;
}

static int aead_tls_init(EVP_AEAD_CTX *ctx, const uint8_t *key, size_t key_len,
                         size_t tag_len, const EVP_CIPHER *cipher,
                         const EVP_MD *md, char implicit_iv) {
  if (tag_len != EVP_AEAD_DEFAULT_TAG_LENGTH &&
      tag_len != EVP_MD_size(md)) {
    OPENSSL_PUT_ERROR(CIPHER, aead_tls_init, CIPHER_R_UNSUPPORTED_TAG_SIZE);
    return 0;
  }

  if (key_len != EVP_AEAD_key_length(ctx->aead)) {
    OPENSSL_PUT_ERROR(CIPHER, aead_tls_init, CIPHER_R_BAD_KEY_LENGTH);
    return 0;
  }

  size_t mac_key_len = EVP_MD_size(md);
  size_t enc_key_len = EVP_CIPHER_key_length(cipher);
  size_t iv_len = implicit_iv ? EVP_CIPHER_iv_length(cipher) : 0;
  assert(mac_key_len + enc_key_len + iv_len == key_len);
  /* Although EVP_rc4() is a variable-length cipher, the default key size is
   * correct for TLS. */

  AEAD_TLS_CTX *tls_ctx = OPENSSL_malloc(sizeof(AEAD_TLS_CTX));
  if (tls_ctx == NULL) {
    OPENSSL_PUT_ERROR(CIPHER, aead_tls_init, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  EVP_CIPHER_CTX_init(&tls_ctx->cipher_ctx);
  HMAC_CTX_init(&tls_ctx->hmac_ctx);
  memcpy(tls_ctx->mac_key, key, mac_key_len);
  tls_ctx->mac_key_len = mac_key_len;
  memcpy(tls_ctx->enc_key, &key[mac_key_len], enc_key_len);
  tls_ctx->enc_key_len = enc_key_len;
  memcpy(tls_ctx->iv, &key[mac_key_len + enc_key_len], iv_len);
  tls_ctx->iv_len = iv_len;
  tls_ctx->implicit_iv = implicit_iv;
  tls_ctx->initialized = 0;

  ctx->aead_state = tls_ctx;
  if (!EVP_CipherInit_ex(&tls_ctx->cipher_ctx, cipher, NULL, NULL, NULL, 0) ||
      !HMAC_Init_ex(&tls_ctx->hmac_ctx, key, mac_key_len, md, NULL)) {
    aead_tls_cleanup(ctx);
    return 0;
  }
  EVP_CIPHER_CTX_set_padding(&tls_ctx->cipher_ctx, 0);

  return 1;
}

static int aead_tls_seal(const EVP_AEAD_CTX *ctx, uint8_t *out,
                         size_t *out_len, size_t max_out_len,
                         const uint8_t *nonce, size_t nonce_len,
                         const uint8_t *in, size_t in_len,
                         const uint8_t *ad, size_t ad_len) {
  AEAD_TLS_CTX *tls_ctx = (AEAD_TLS_CTX *)ctx->aead_state;
  size_t total = 0;

  if (in_len + EVP_AEAD_max_overhead(ctx->aead) < in_len ||
      in_len > INT_MAX) {
    /* EVP_CIPHER takes int as input. */
    OPENSSL_PUT_ERROR(CIPHER, aead_tls_seal, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (max_out_len < in_len + EVP_AEAD_max_overhead(ctx->aead)) {
    OPENSSL_PUT_ERROR(CIPHER, aead_tls_seal, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (nonce_len != EVP_AEAD_nonce_length(ctx->aead)) {
    OPENSSL_PUT_ERROR(CIPHER, aead_tls_seal, CIPHER_R_INVALID_NONCE_SIZE);
    return 0;
  }

  if (ad_len != 13 - 2) {
    OPENSSL_PUT_ERROR(CIPHER, aead_tls_seal, CIPHER_R_INVALID_AD_SIZE);
    return 0;
  }

  if (!tls_ctx->initialized) {
    /* Finish initializing the EVP_CIPHER_CTX now that the direction is
     * known. */
    if (!EVP_EncryptInit_ex(&tls_ctx->cipher_ctx, NULL, NULL, tls_ctx->enc_key,
                            tls_ctx->implicit_iv ? tls_ctx->iv : NULL)) {
      return 0;
    }
    tls_ctx->initialized = 1;
  } else if (!tls_ctx->cipher_ctx.encrypt) {
    /* Unlike a normal AEAD, using a TLS AEAD once freezes the direction. */
    OPENSSL_PUT_ERROR(CIPHER, aead_tls_seal, CIPHER_R_INVALID_OPERATION);
    return 0;
  }

  /* To allow for CBC mode which changes cipher length, |ad| doesn't include the
   * length for legacy ciphers. */
  uint8_t ad_extra[2];
  ad_extra[0] = (uint8_t)(in_len >> 8);
  ad_extra[1] = (uint8_t)(in_len & 0xff);

  /* Compute the MAC. This must be first in case the operation is being done
   * in-place. */
  uint8_t mac[EVP_MAX_MD_SIZE];
  unsigned mac_len;
  HMAC_CTX hmac_ctx;
  HMAC_CTX_init(&hmac_ctx);
  if (!HMAC_CTX_copy_ex(&hmac_ctx, &tls_ctx->hmac_ctx) ||
      !HMAC_Update(&hmac_ctx, ad, ad_len) ||
      !HMAC_Update(&hmac_ctx, ad_extra, sizeof(ad_extra)) ||
      !HMAC_Update(&hmac_ctx, in, in_len) ||
      !HMAC_Final(&hmac_ctx, mac, &mac_len)) {
    HMAC_CTX_cleanup(&hmac_ctx);
    return 0;
  }
  HMAC_CTX_cleanup(&hmac_ctx);

  /* Configure the explicit IV. */
  if (EVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) == EVP_CIPH_CBC_MODE &&
      !tls_ctx->implicit_iv) {
    if (!EVP_EncryptInit_ex(&tls_ctx->cipher_ctx, NULL, NULL, NULL, nonce)) {
      return 0;
    }
  }

  /* Encrypt the input. */
  int len;
  if (!EVP_EncryptUpdate(&tls_ctx->cipher_ctx, out, &len, in,
                         (int)in_len)) {
    return 0;
  }
  total = len;

  /* Feed the MAC into the cipher. */
  if (!EVP_EncryptUpdate(&tls_ctx->cipher_ctx, out + total, &len, mac,
                         (int)mac_len)) {
    return 0;
  }
  total += len;

  unsigned block_size = EVP_CIPHER_CTX_block_size(&tls_ctx->cipher_ctx);
  if (block_size > 1) {
    assert(block_size <= 256);
    assert(EVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) == EVP_CIPH_CBC_MODE);

    /* Compute padding and feed that into the cipher. */
    uint8_t padding[256];
    unsigned padding_len = block_size - ((in_len + mac_len) % block_size);
    memset(padding, padding_len - 1, padding_len);
    if (!EVP_EncryptUpdate(&tls_ctx->cipher_ctx, out + total, &len, padding,
                           (int)padding_len)) {
      return 0;
    }
    total += len;
  }

  if (!EVP_EncryptFinal_ex(&tls_ctx->cipher_ctx, out + total, &len)) {
    return 0;
  }
  total += len;

  *out_len = total;
  return 1;
}

static int aead_tls_open(const EVP_AEAD_CTX *ctx, uint8_t *out,
                         size_t *out_len, size_t max_out_len,
                         const uint8_t *nonce, size_t nonce_len,
                         const uint8_t *in, size_t in_len,
                         const uint8_t *ad, size_t ad_len) {
  AEAD_TLS_CTX *tls_ctx = (AEAD_TLS_CTX *)ctx->aead_state;

  if (in_len < HMAC_size(&tls_ctx->hmac_ctx)) {
    OPENSSL_PUT_ERROR(CIPHER, aead_tls_open, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  if (max_out_len < in_len) {
    /* This requires the caller provide space for the MAC, even though it will
     * always be removed on return. */
    OPENSSL_PUT_ERROR(CIPHER, aead_tls_open, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (nonce_len != EVP_AEAD_nonce_length(ctx->aead)) {
    OPENSSL_PUT_ERROR(CIPHER, aead_tls_open, CIPHER_R_INVALID_NONCE_SIZE);
    return 0;
  }

  if (ad_len != 13 - 2) {
    OPENSSL_PUT_ERROR(CIPHER, aead_tls_open, CIPHER_R_INVALID_AD_SIZE);
    return 0;
  }

  if (in_len > INT_MAX) {
    /* EVP_CIPHER takes int as input. */
    OPENSSL_PUT_ERROR(CIPHER, aead_tls_open, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (!tls_ctx->initialized) {
    /* Finish initializing the EVP_CIPHER_CTX now that the direction is
     * known. */
    if (!EVP_DecryptInit_ex(&tls_ctx->cipher_ctx, NULL, NULL, tls_ctx->enc_key,
                            tls_ctx->implicit_iv ? tls_ctx->iv : NULL)) {
      return 0;
    }
    tls_ctx->initialized = 1;
  } else if (tls_ctx->cipher_ctx.encrypt) {
    /* Unlike a normal AEAD, using a TLS AEAD once freezes the direction. */
    OPENSSL_PUT_ERROR(CIPHER, aead_tls_open, CIPHER_R_INVALID_OPERATION);
    return 0;
  }

  /* Configure the explicit IV. */
  if (EVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) == EVP_CIPH_CBC_MODE &&
      !tls_ctx->implicit_iv) {
    if (!EVP_DecryptInit_ex(&tls_ctx->cipher_ctx, NULL, NULL, NULL, nonce)) {
      return 0;
    }
  }

  /* Decrypt to get the plaintext + MAC + padding. */
  size_t total = 0;
  int len;
  if (!EVP_DecryptUpdate(&tls_ctx->cipher_ctx, out, &len, in, (int)in_len)) {
    return 0;
  }
  total += len;
  if (!EVP_DecryptFinal_ex(&tls_ctx->cipher_ctx, out + total, &len)) {
    return 0;
  }
  total += len;
  assert(total == in_len);

  /* Remove CBC padding. Code from here on is timing-sensitive with respect to
   * |padding_ok| and |data_plus_mac_len| for CBC ciphers. */
  int padding_ok;
  unsigned data_plus_mac_len, data_len;
  if (EVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) == EVP_CIPH_CBC_MODE) {
    padding_ok = EVP_tls_cbc_remove_padding(
        &data_plus_mac_len, out, total,
        EVP_CIPHER_CTX_block_size(&tls_ctx->cipher_ctx),
        (unsigned)HMAC_size(&tls_ctx->hmac_ctx));
    /* Publicly invalid. This can be rejected in non-constant time. */
    if (padding_ok == 0) {
      OPENSSL_PUT_ERROR(CIPHER, aead_tls_open, CIPHER_R_BAD_DECRYPT);
      return 0;
    }
    data_len = data_plus_mac_len - HMAC_size(&tls_ctx->hmac_ctx);
  } else {
    padding_ok = 1;
    data_plus_mac_len = total;
    if (data_plus_mac_len < HMAC_size(&tls_ctx->hmac_ctx)) {
      OPENSSL_PUT_ERROR(CIPHER, aead_tls_open, CIPHER_R_BAD_DECRYPT);
      return 0;
    }
    data_len = data_plus_mac_len - HMAC_size(&tls_ctx->hmac_ctx);
  }

  /* At this point, |padding_ok| is 1 or -1. If 1, the padding is valid and the
   * first |data_plus_mac_size| bytes after |out| are the plaintext and
   * MAC. Either way, |data_plus_mac_size| is large enough to extract a MAC. */

  /* To allow for CBC mode which changes cipher length, |ad| doesn't include the
   * length for legacy ciphers. */
  uint8_t ad_fixed[13];
  memcpy(ad_fixed, ad, 11);
  ad_fixed[11] = (uint8_t)(data_len >> 8);
  ad_fixed[12] = (uint8_t)(data_len & 0xff);
  ad_len += 2;

  /* Compute the MAC and extract the one in the record. */
  uint8_t mac[EVP_MAX_MD_SIZE];
  size_t mac_len;
  uint8_t record_mac_tmp[EVP_MAX_MD_SIZE];
  uint8_t *record_mac;
  if (EVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) == EVP_CIPH_CBC_MODE &&
      EVP_tls_cbc_record_digest_supported(tls_ctx->hmac_ctx.md)) {
    if (!EVP_tls_cbc_digest_record(tls_ctx->hmac_ctx.md, mac, &mac_len,
                                   ad_fixed, out, data_plus_mac_len, total,
                                   tls_ctx->mac_key, tls_ctx->mac_key_len)) {
      OPENSSL_PUT_ERROR(CIPHER, aead_tls_open, CIPHER_R_BAD_DECRYPT);
      return 0;
    }
    assert(mac_len == HMAC_size(&tls_ctx->hmac_ctx));

    record_mac = record_mac_tmp;
    EVP_tls_cbc_copy_mac(record_mac, mac_len, out, data_plus_mac_len, total);
  } else {
    /* We should support the constant-time path for all CBC-mode ciphers
     * implemented. */
    assert(EVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) != EVP_CIPH_CBC_MODE);

    HMAC_CTX hmac_ctx;
    HMAC_CTX_init(&hmac_ctx);
    unsigned mac_len_u;
    if (!HMAC_CTX_copy_ex(&hmac_ctx, &tls_ctx->hmac_ctx) ||
        !HMAC_Update(&hmac_ctx, ad_fixed, ad_len) ||
        !HMAC_Update(&hmac_ctx, out, data_len) ||
        !HMAC_Final(&hmac_ctx, mac, &mac_len_u)) {
      HMAC_CTX_cleanup(&hmac_ctx);
      return 0;
    }
    mac_len = mac_len_u;
    HMAC_CTX_cleanup(&hmac_ctx);

    assert(mac_len == HMAC_size(&tls_ctx->hmac_ctx));
    record_mac = &out[data_len];
  }

  /* Check the MAC and padding together. Strictly speaking, we can simply check
   * the MAC first and then the padding in non-constant time. If |padding_ok| is
   * -1, |padding_len| is treated as zero rather than a function of the
   * input. (So failing the padding check after passing the MAC check means the
   * plaintext had a correct MAC but no padding.)
   *
   * However if, say, a padding of [<15 arbitrary bytes> 15] gave |padding_ok|
   * of -1 and |padding_len| of 16, distinguishing the two cases would give
   * POODLE again. So just do the whole thing in constant time to avoid
   * caring. */
  unsigned good = constant_time_is_zero(
      (unsigned)CRYPTO_memcmp(record_mac, mac, mac_len));
  good &= constant_time_eq_int(padding_ok, 1);
  if (!good) {
    OPENSSL_PUT_ERROR(CIPHER, aead_tls_open, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  /* End of timing-sensitive code. */

  *out_len = data_len;
  return 1;
}

static int aead_rc4_sha1_tls_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                  size_t key_len, size_t tag_len) {
  return aead_tls_init(ctx, key, key_len, tag_len, EVP_rc4(), EVP_sha1(), 0);
}

static int aead_aes_128_cbc_sha1_tls_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                          size_t key_len, size_t tag_len) {
  return aead_tls_init(ctx, key, key_len, tag_len, EVP_aes_128_cbc(),
                       EVP_sha1(), 0);
}

static int aead_aes_128_cbc_sha1_tls_implicit_iv_init(EVP_AEAD_CTX *ctx,
                                                      const uint8_t *key,
                                                      size_t key_len,
                                                      size_t tag_len) {
  return aead_tls_init(ctx, key, key_len, tag_len, EVP_aes_128_cbc(),
                       EVP_sha1(), 1);
}

static int aead_aes_128_cbc_sha256_tls_init(EVP_AEAD_CTX *ctx,
                                            const uint8_t *key, size_t key_len,
                                            size_t tag_len) {
  return aead_tls_init(ctx, key, key_len, tag_len, EVP_aes_128_cbc(),
                       EVP_sha256(), 0);
}

static int aead_aes_256_cbc_sha1_tls_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                          size_t key_len, size_t tag_len) {
  return aead_tls_init(ctx, key, key_len, tag_len, EVP_aes_256_cbc(),
                       EVP_sha1(), 0);
}

static int aead_aes_256_cbc_sha1_tls_implicit_iv_init(EVP_AEAD_CTX *ctx,
                                                      const uint8_t *key,
                                                      size_t key_len,
                                                      size_t tag_len) {
  return aead_tls_init(ctx, key, key_len, tag_len, EVP_aes_256_cbc(),
                       EVP_sha1(), 1);
}

static int aead_aes_256_cbc_sha256_tls_init(EVP_AEAD_CTX *ctx,
                                            const uint8_t *key, size_t key_len,
                                            size_t tag_len) {
  return aead_tls_init(ctx, key, key_len, tag_len, EVP_aes_256_cbc(),
                       EVP_sha256(), 0);
}

static int aead_aes_256_cbc_sha384_tls_init(EVP_AEAD_CTX *ctx,
                                            const uint8_t *key, size_t key_len,
                                            size_t tag_len) {
  return aead_tls_init(ctx, key, key_len, tag_len, EVP_aes_256_cbc(),
                       EVP_sha384(), 0);
}

static int aead_des_ede3_cbc_sha1_tls_init(EVP_AEAD_CTX *ctx,
                                           const uint8_t *key, size_t key_len,
                                           size_t tag_len) {
  return aead_tls_init(ctx, key, key_len, tag_len, EVP_des_ede3_cbc(),
                       EVP_sha1(), 0);
}

static int aead_des_ede3_cbc_sha1_tls_implicit_iv_init(EVP_AEAD_CTX *ctx,
                                                       const uint8_t *key,
                                                       size_t key_len,
                                                       size_t tag_len) {
  return aead_tls_init(ctx, key, key_len, tag_len, EVP_des_ede3_cbc(),
                       EVP_sha1(), 1);
}

static const EVP_AEAD aead_rc4_sha1_tls = {
    SHA_DIGEST_LENGTH + 16, /* key len (SHA1 + RC4) */
    0,                      /* nonce len */
    SHA_DIGEST_LENGTH,      /* overhead */
    SHA_DIGEST_LENGTH,      /* max tag length */
    aead_rc4_sha1_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
};

static const EVP_AEAD aead_aes_128_cbc_sha1_tls = {
    SHA_DIGEST_LENGTH + 16, /* key len (SHA1 + AES128) */
    16,                     /* nonce len (IV) */
    16 + SHA_DIGEST_LENGTH, /* overhead (padding + SHA1) */
    SHA_DIGEST_LENGTH,      /* max tag length */
    aead_aes_128_cbc_sha1_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
};

static const EVP_AEAD aead_aes_128_cbc_sha1_tls_implicit_iv = {
    SHA_DIGEST_LENGTH + 16 + 16, /* key len (SHA1 + AES128 + IV) */
    0,                           /* nonce len */
    16 + SHA_DIGEST_LENGTH,      /* overhead (padding + SHA1) */
    SHA_DIGEST_LENGTH,           /* max tag length */
    aead_aes_128_cbc_sha1_tls_implicit_iv_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
};

static const EVP_AEAD aead_aes_128_cbc_sha256_tls = {
    SHA256_DIGEST_LENGTH + 16, /* key len (SHA256 + AES128) */
    16,                        /* nonce len (IV) */
    16 + SHA256_DIGEST_LENGTH, /* overhead (padding + SHA256) */
    SHA_DIGEST_LENGTH,         /* max tag length */
    aead_aes_128_cbc_sha256_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
};

static const EVP_AEAD aead_aes_256_cbc_sha1_tls = {
    SHA_DIGEST_LENGTH + 32, /* key len (SHA1 + AES256) */
    16,                     /* nonce len (IV) */
    16 + SHA_DIGEST_LENGTH, /* overhead (padding + SHA1) */
    SHA_DIGEST_LENGTH,      /* max tag length */
    aead_aes_256_cbc_sha1_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
};

static const EVP_AEAD aead_aes_256_cbc_sha1_tls_implicit_iv = {
    SHA_DIGEST_LENGTH + 32 + 16, /* key len (SHA1 + AES256 + IV) */
    0,                           /* nonce len */
    16 + SHA_DIGEST_LENGTH,      /* overhead (padding + SHA1) */
    SHA_DIGEST_LENGTH,           /* max tag length */
    aead_aes_256_cbc_sha1_tls_implicit_iv_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
};

static const EVP_AEAD aead_aes_256_cbc_sha256_tls = {
    SHA256_DIGEST_LENGTH + 32, /* key len (SHA256 + AES256) */
    16,                        /* nonce len (IV) */
    16 + SHA256_DIGEST_LENGTH, /* overhead (padding + SHA256) */
    SHA_DIGEST_LENGTH,         /* max tag length */
    aead_aes_256_cbc_sha256_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
};

static const EVP_AEAD aead_aes_256_cbc_sha384_tls = {
    SHA384_DIGEST_LENGTH + 32, /* key len (SHA384 + AES256) */
    16,                        /* nonce len (IV) */
    16 + SHA384_DIGEST_LENGTH, /* overhead (padding + SHA384) */
    SHA_DIGEST_LENGTH,         /* max tag length */
    aead_aes_256_cbc_sha384_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
};

static const EVP_AEAD aead_des_ede3_cbc_sha1_tls = {
    SHA_DIGEST_LENGTH + 24, /* key len (SHA1 + 3DES) */
    8,                      /* nonce len (IV) */
    8 + SHA_DIGEST_LENGTH,  /* overhead (padding + SHA1) */
    SHA_DIGEST_LENGTH,      /* max tag length */
    aead_des_ede3_cbc_sha1_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
};

static const EVP_AEAD aead_des_ede3_cbc_sha1_tls_implicit_iv = {
    SHA_DIGEST_LENGTH + 24 + 8, /* key len (SHA1 + 3DES + IV) */
    0,                          /* nonce len */
    8 + SHA_DIGEST_LENGTH,      /* overhead (padding + SHA1) */
    SHA_DIGEST_LENGTH,          /* max tag length */
    aead_des_ede3_cbc_sha1_tls_implicit_iv_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
};

const EVP_AEAD *EVP_aead_rc4_sha1_tls(void) { return &aead_rc4_sha1_tls; }

const EVP_AEAD *EVP_aead_aes_128_cbc_sha1_tls(void) {
  return &aead_aes_128_cbc_sha1_tls;
}

const EVP_AEAD *EVP_aead_aes_128_cbc_sha1_tls_implicit_iv(void) {
  return &aead_aes_128_cbc_sha1_tls_implicit_iv;
}

const EVP_AEAD *EVP_aead_aes_128_cbc_sha256_tls(void) {
  return &aead_aes_128_cbc_sha256_tls;
}

const EVP_AEAD *EVP_aead_aes_256_cbc_sha1_tls(void) {
  return &aead_aes_256_cbc_sha1_tls;
}

const EVP_AEAD *EVP_aead_aes_256_cbc_sha1_tls_implicit_iv(void) {
  return &aead_aes_256_cbc_sha1_tls_implicit_iv;
}

const EVP_AEAD *EVP_aead_aes_256_cbc_sha256_tls(void) {
  return &aead_aes_256_cbc_sha256_tls;
}

const EVP_AEAD *EVP_aead_aes_256_cbc_sha384_tls(void) {
  return &aead_aes_256_cbc_sha384_tls;
}

const EVP_AEAD *EVP_aead_des_ede3_cbc_sha1_tls(void) {
  return &aead_des_ede3_cbc_sha1_tls;
}

const EVP_AEAD *EVP_aead_des_ede3_cbc_sha1_tls_implicit_iv(void) {
  return &aead_des_ede3_cbc_sha1_tls_implicit_iv;
}
