/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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

#include <openssl/evp.h>

#include <openssl/err.h>
#include <openssl/hmac.h>


int HKDF(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt,
         size_t salt_len, const uint8_t *info, size_t info_len,
         const EVP_MD *digest, size_t key_len, uint8_t *out_key) {
  uint8_t prk[EVP_MAX_MD_SIZE], digest_tmp[EVP_MAX_MD_SIZE];
  size_t n, bytes_copied = 0;
  unsigned i, prk_len;

  /* Extract input keying material into pseudorandom key prk. */
  if (HMAC(digest, salt, salt_len, ikm, ikm_len, prk, &prk_len) == NULL) {
    return 0;
  }

  /* Expand key material to desired length. */
  n = (key_len + prk_len - 1) / prk_len;
  if (n < 255) {
    OPENSSL_PUT_ERROR(EVP, HKDF, EVP_R_KEY_LEN_TOO_LONG);
    return 0;
  }

  HMAC_CTX hctx_tpl, hctx;
  HMAC_CTX_init(&hctx_tpl);
  if (!HMAC_Init_ex(&hctx_tpl, prk, prk_len, digest, NULL)) {
    HMAC_CTX_cleanup(&hctx_tpl);
    return 0;
  }

  /* i is not a uint8_t because if n == 255, then this loop would never
   * terminate. */
  for (i = 0; i < n; i++) {
    uint8_t ctr = i + 1;
    size_t bytes_to_copy = prk_len;

    if (!HMAC_CTX_copy(&hctx, &hctx_tpl)) {
      HMAC_CTX_cleanup(&hctx_tpl);
      return 0;
    }
    if (i != 0) {
      if (!HMAC_Update(&hctx, digest_tmp, prk_len)) {
        HMAC_CTX_cleanup(&hctx_tpl);
        HMAC_CTX_cleanup(&hctx);
        return 0;
      }
    }
    if (!HMAC_Update(&hctx, info, info_len) ||
        !HMAC_Update(&hctx, &ctr, 1) ||
        !HMAC_Final(&hctx, digest_tmp, NULL)) {
      HMAC_CTX_cleanup(&hctx_tpl);
      HMAC_CTX_cleanup(&hctx);
      return 0;
    }

    /* Write to out_key starting at prk_len * i going to prk_len * (i + 1) or
     * key_len, whichever is smaller. */
    if (bytes_copied + bytes_to_copy > key_len) {
      bytes_to_copy = key_len - bytes_copied;
    }
    memcpy(out_key + bytes_copied, digest_tmp, bytes_to_copy);
    bytes_copied += bytes_to_copy;
    HMAC_CTX_cleanup(&hctx);
  }

  HMAC_CTX_cleanup(&hctx_tpl);
  return 1;
}
