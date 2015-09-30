/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.] */

#ifndef OPENSSL_HEADER_CIPHER_INTERNAL_H
#define OPENSSL_HEADER_CIPHER_INTERNAL_H

#if !defined(__STDC_CONSTANT_MACROS)
#define __STDC_CONSTANT_MACROS
#endif

#include <openssl/base.h>

#include <assert.h>
#include <stdint.h>

#include <openssl/aead.h>
#include <openssl/err.h>

#include "../internal.h"

#if defined(__cplusplus)
extern "C" {
#endif


/* EVP_CIPH_MODE_MASK contains the bits of |flags| that represent the mode. */
#define EVP_CIPH_MODE_MASK 0x3f


/* EVP_AEAD represents a specific AEAD algorithm. */
struct evp_aead_st {
  uint8_t key_len;
  uint8_t nonce_len;
  uint8_t overhead;
  uint8_t max_tag_len;

  /* init initialises an |EVP_AEAD_CTX|. If this call returns zero then
   * |cleanup| will not be called for that context. */
  int (*init)(EVP_AEAD_CTX *, const uint8_t *key, size_t key_len,
              size_t tag_len);
  int (*init_with_direction)(EVP_AEAD_CTX *, const uint8_t *key, size_t key_len,
                             size_t tag_len, enum evp_aead_direction_t dir);
  void (*cleanup)(EVP_AEAD_CTX *);

  int (*seal)(const EVP_AEAD_CTX *ctx, uint8_t *out, size_t *out_len,
              size_t max_out_len, const uint8_t *nonce, size_t nonce_len,
              const uint8_t *in, size_t in_len, const uint8_t *ad,
              size_t ad_len);

  int (*open)(const EVP_AEAD_CTX *ctx, uint8_t *out, size_t *out_len,
              size_t max_out_len, const uint8_t *nonce, size_t nonce_len,
              const uint8_t *in, size_t in_len, const uint8_t *ad,
              size_t ad_len);

  int (*get_rc4_state)(const EVP_AEAD_CTX *ctx, const RC4_KEY **out_key);
};


/* EVP_tls_cbc_get_padding determines the padding from the decrypted, TLS, CBC
 * record in |in|. This decrypted record should not include any "decrypted"
 * explicit IV. It sets |*out_len| to the length with the padding removed or
 * |in_len| if invalid.
 *
 * block_size: the block size of the cipher used to encrypt the record.
 * returns:
 *   0: (in non-constant time) if the record is publicly invalid.
 *   1: if the padding was valid
 *  -1: otherwise. */
int EVP_tls_cbc_remove_padding(unsigned *out_len,
                               const uint8_t *in, unsigned in_len,
                               unsigned block_size, unsigned mac_size);

/* EVP_tls_cbc_copy_mac copies |md_size| bytes from the end of the first
 * |in_len| bytes of |in| to |out| in constant time (independent of the concrete
 * value of |in_len|, which may vary within a 256-byte window). |in| must point
 * to a buffer of |orig_len| bytes.
 *
 * On entry:
 *   orig_len >= in_len >= md_size
 *   md_size <= EVP_MAX_MD_SIZE */
void EVP_tls_cbc_copy_mac(uint8_t *out, unsigned md_size,
                          const uint8_t *in, unsigned in_len,
                          unsigned orig_len);

/* EVP_tls_cbc_record_digest_supported returns 1 iff |md| is a hash function
 * which EVP_tls_cbc_digest_record supports. */
int EVP_tls_cbc_record_digest_supported(const EVP_MD *md);

/* EVP_tls_cbc_digest_record computes the MAC of a decrypted, padded TLS
 * record.
 *
 *   md: the hash function used in the HMAC.
 *     EVP_tls_cbc_record_digest_supported must return true for this hash.
 *   md_out: the digest output. At most EVP_MAX_MD_SIZE bytes will be written.
 *   md_out_size: the number of output bytes is written here.
 *   header: the 13-byte, TLS record header.
 *   data: the record data itself
 *   data_plus_mac_size: the secret, reported length of the data and MAC
 *     once the padding has been removed.
 *   data_plus_mac_plus_padding_size: the public length of the whole
 *     record, including padding.
 *
 * On entry: by virtue of having been through one of the remove_padding
 * functions, above, we know that data_plus_mac_size is large enough to contain
 * a padding byte and MAC. (If the padding was invalid, it might contain the
 * padding too. ) */
int EVP_tls_cbc_digest_record(const EVP_MD *md, uint8_t *md_out,
                              size_t *md_out_size, const uint8_t header[13],
                              const uint8_t *data, size_t data_plus_mac_size,
                              size_t data_plus_mac_plus_padding_size,
                              const uint8_t *mac_secret,
                              unsigned mac_secret_length);


/* Preconditions for AEAD implementation methods. */

/* aead_check_alias returns 0 if |out| points within the buffer determined by
 * |in| and |in_len| and 1 otherwise.
 *
 * When processing, there's only an issue if |out| points within in[:in_len]
 * and isn't equal to |in|. If that's the case then writing the output will
 * stomp input that hasn't been read yet.
 *
 * This function checks for that case. */
inline int aead_check_alias(const uint8_t *in, size_t in_len,
                            const uint8_t *out) {
  if (out <= in) {
    return 1;
  } else if (in + in_len <= out) {
    return 1;
  }
  return 0;
}

/* The underlying ChaCha implementation may not support inputs larger than
 * 256GB at a time so we disallow even more huge inputs for all AEADs.
 * |in_len_64| is needed because, on 32-bit platforms, size_t is only
 * 32-bits and this produces a warning because it's always false.
 * Casting to uint64_t inside the conditional is not sufficient to stop
 * the warning. */
inline int aead_check_in_len(size_t in_len) {
  const uint64_t in_len_64 = in_len;
  return in_len_64 < (1ull << 32) * 64 - 64;
}

inline int aead_seal_out_max_out_in_tag_len(size_t *out_len, size_t max_out_len,
                                            size_t in_len, size_t tag_len) {
  if (SIZE_MAX - tag_len < in_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }
  size_t ciphertext_len = in_len + tag_len;
  if (max_out_len < ciphertext_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }
  *out_len = ciphertext_len;
  return 1;
}

inline int aead_open_out_max_out_in_tag_len(size_t *out_len, size_t max_out_len,
                                            size_t in_len, size_t tag_len) {
  if (in_len < tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }
  size_t plaintext_len = in_len - tag_len;
  if (max_out_len < plaintext_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }
  *out_len = plaintext_len;
  return 1;
}

inline void aead_assert_init_preconditions(const EVP_AEAD_CTX *ctx,
                                           const uint8_t *key, size_t key_len,
                                           size_t tag_len) {
  assert(ctx != NULL);
  assert(ctx->aead != NULL);
  assert(ctx->aead->overhead >= ctx->aead->max_tag_len);

  /* ctx->aead_state may be NULL. */
  assert(key != NULL);
  assert(key_len == ctx->aead->key_len);

  /* A tag length of 0 means "use the default," and the caller must have
   * already substituted the default in. */
  assert(tag_len > 0);
  assert(tag_len <= ctx->aead->max_tag_len);
}

inline void aead_assert_open_seal_preconditions(const EVP_AEAD_CTX *ctx,
                                                uint8_t *out, size_t *out_len,
                                                const uint8_t *nonce,
                                                size_t nonce_len,
                                                const uint8_t *in,
                                                size_t in_len,
                                                const uint8_t *ad,
                                                size_t ad_len) {
  assert(ctx != NULL);
  assert(ctx->aead != NULL);
  assert(ctx->aead_state != NULL);
  assert(out != NULL);
  assert(out_len != NULL);
  assert(nonce != NULL || nonce_len == 0);
  assert(nonce_len > 0 || ctx->aead->nonce_len == 0);
  /* TODO: assert(nonce_len == ctx->aead->nonce_len); */
  assert(in != NULL || in_len == 0);
  assert(aead_check_in_len(in_len));
  assert(aead_check_alias(in, in_len, out));
  assert(ad != NULL || ad_len == 0);
}

#if defined(__cplusplus)
} /* extern C */
#endif

#endif /* OPENSSL_HEADER_CIPHER_INTERNAL_H */
