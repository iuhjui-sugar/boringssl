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
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
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
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <assert.h>
#include <string.h>

#include <openssl/aead.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/type_check.h>

#include "internal.h"


OPENSSL_COMPILE_ASSERT(EVP_AEAD_MAX_NONCE_LENGTH < 256,
                       variable_nonce_len_fits_in_uint8_t);

SSL_AEAD_CTX *SSL_AEAD_CTX_new(enum evp_aead_direction_t direction,
                               uint16_t version, const SSL_CIPHER *cipher,
                               const uint8_t *enc_key, size_t enc_key_len,
                               const uint8_t *mac_key, size_t mac_key_len,
                               const uint8_t *fixed_iv, size_t fixed_iv_len) {
  uint8_t merged_key[EVP_AEAD_MAX_KEY_LENGTH];
  const EVP_AEAD *aead;
  size_t discard;

  if (!ssl_cipher_get_evp_aead(&aead, &discard, &discard, cipher, version)) {
    OPENSSL_PUT_ERROR(SSL, SSL_AEAD_CTX_new, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  if (mac_key_len > 0) {
    /* This is a "stateful" AEAD (for compatibility with pre-AEAD cipher
     * suites). */
    if (mac_key_len + enc_key_len + fixed_iv_len > sizeof(merged_key)) {
      OPENSSL_PUT_ERROR(SSL, SSL_AEAD_CTX_new, ERR_R_INTERNAL_ERROR);
      return 0;
    }
    memcpy(merged_key, mac_key, mac_key_len);
    memcpy(merged_key + mac_key_len, enc_key, enc_key_len);
    memcpy(merged_key + mac_key_len + enc_key_len, fixed_iv, fixed_iv_len);
    enc_key = merged_key;
    enc_key_len += mac_key_len;
    enc_key_len += fixed_iv_len;
  }

  SSL_AEAD_CTX *aead_ctx = (SSL_AEAD_CTX *)OPENSSL_malloc(sizeof(SSL_AEAD_CTX));
  if (aead_ctx == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_AEAD_CTX_new, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  aead_ctx->cipher = cipher;

  if (!EVP_AEAD_CTX_init_with_direction(
          &aead_ctx->ctx, aead, enc_key, enc_key_len,
          EVP_AEAD_DEFAULT_TAG_LENGTH, direction)) {
    OPENSSL_free(aead_ctx);
    return NULL;
  }

  assert(EVP_AEAD_nonce_length(aead) <= EVP_AEAD_MAX_NONCE_LENGTH);
  aead_ctx->variable_nonce_len = (uint8_t)EVP_AEAD_nonce_length(aead);
  if (mac_key_len == 0) {
    /* For a real AEAD, the IV is the fixed part of the nonce. */
    if (fixed_iv_len > sizeof(aead_ctx->fixed_nonce) ||
        fixed_iv_len > aead_ctx->variable_nonce_len) {
      OPENSSL_PUT_ERROR(SSL, SSL_AEAD_CTX_new, ERR_R_INTERNAL_ERROR);
      return 0;
    }
    aead_ctx->variable_nonce_len -= fixed_iv_len;

    memcpy(aead_ctx->fixed_nonce, fixed_iv, fixed_iv_len);
    aead_ctx->fixed_nonce_len = fixed_iv_len;
    aead_ctx->variable_nonce_included_in_record =
        (cipher->algorithm2 &
         SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_INCLUDED_IN_RECORD) != 0;
    aead_ctx->random_variable_nonce = 0;
    aead_ctx->omit_length_in_ad = 0;
    aead_ctx->omit_version_in_ad = 0;
  } else {
    aead_ctx->fixed_nonce_len = 0;
    aead_ctx->variable_nonce_included_in_record = 1;
    aead_ctx->random_variable_nonce = 1;
    aead_ctx->omit_length_in_ad = 1;
    aead_ctx->omit_version_in_ad = (version == SSL3_VERSION);
  }

  return aead_ctx;
}

void SSL_AEAD_CTX_free(SSL_AEAD_CTX *aead) {
  if (aead == NULL) {
    return;
  }
  EVP_AEAD_CTX_cleanup(&aead->ctx);
  OPENSSL_free(aead);
}

size_t SSL_AEAD_CTX_explicit_nonce_len(SSL_AEAD_CTX *aead) {
  if (aead != NULL && aead->variable_nonce_included_in_record) {
    return aead->variable_nonce_len;
  }
  return 0;
}

size_t SSL_AEAD_CTX_max_overhead(SSL_AEAD_CTX *aead) {
  if (aead == NULL) {
    return 0;
  }
  return EVP_AEAD_max_overhead(aead->ctx.aead) +
      SSL_AEAD_CTX_explicit_nonce_len(aead);
}

/* ssl_aead_ctx_get_ad writes the additional data for |aead| into |out| and
 * returns the number of bytes written. */
static size_t ssl_aead_ctx_get_ad(SSL_AEAD_CTX *aead, uint8_t out[13],
                                  uint8_t type, uint16_t wire_version,
                                  const uint8_t seqnum[8],
                                  size_t plaintext_len) {
  memcpy(out, seqnum, 8);
  size_t len = 8;
  out[len++] = type;
  if (!aead->omit_version_in_ad) {
    out[len++] = (uint8_t)(wire_version >> 8);
    out[len++] = (uint8_t)wire_version;
  }
  if (!aead->omit_length_in_ad) {
    out[len++] = (uint8_t)(plaintext_len >> 8);
    out[len++] = (uint8_t)plaintext_len;
  }
  return len;
}

int SSL_AEAD_CTX_open(SSL_AEAD_CTX *aead, uint8_t *out, size_t *out_len,
                      size_t max_out, uint8_t type, uint16_t wire_version,
                      const uint8_t seqnum[8], const uint8_t *in,
                      size_t in_len) {
  if (aead == NULL) {
    /* Handle the initial NULL cipher. */
    if (in_len > max_out) {
      OPENSSL_PUT_ERROR(SSL, SSL_AEAD_CTX_open, SSL_R_BUFFER_TOO_SMALL);
      return 0;
    }
    memmove(out, in, in_len);
    *out_len = in_len;
    return 1;
  }

  /* TLS 1.2 AEADs include the length in the AD and are assumed to have fixed
   * overhead. Otherwise the parameter is unused. */
  size_t plaintext_len = 0;
  if (!aead->omit_length_in_ad) {
    size_t overhead = SSL_AEAD_CTX_max_overhead(aead);
    if (in_len < overhead) {
      /* Publicly invalid. */
      OPENSSL_PUT_ERROR(SSL, SSL_AEAD_CTX_open, SSL_R_BAD_PACKET_LENGTH);
      return 0;
    }
    plaintext_len = in_len - overhead;
  }
  uint8_t ad[13];
  size_t ad_len = ssl_aead_ctx_get_ad(aead, ad, type, wire_version, seqnum,
                                      plaintext_len);

  /* Assemble the nonce. */
  uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH];
  size_t nonce_len = 0;
  memcpy(nonce, aead->fixed_nonce, aead->fixed_nonce_len);
  nonce_len += aead->fixed_nonce_len;
  if (aead->variable_nonce_included_in_record) {
    if (in_len < aead->variable_nonce_len) {
      /* Publicly invalid. */
      OPENSSL_PUT_ERROR(SSL, SSL_AEAD_CTX_open, SSL_R_BAD_PACKET_LENGTH);
      return 0;
    }
    memcpy(nonce + nonce_len, in, aead->variable_nonce_len);
    in += aead->variable_nonce_len;
    in_len -= aead->variable_nonce_len;
  } else {
    assert(aead->variable_nonce_len == 8);
    memcpy(nonce + nonce_len, seqnum, aead->variable_nonce_len);
  }
  nonce_len += aead->variable_nonce_len;

  return EVP_AEAD_CTX_open(&aead->ctx, out, out_len, max_out, nonce, nonce_len,
                           in, in_len, ad, ad_len);
}

int SSL_AEAD_CTX_seal(SSL_AEAD_CTX *aead, uint8_t *out, size_t *out_len,
                      size_t max_out, uint8_t type, uint16_t wire_version,
                      const uint8_t seqnum[8], const uint8_t *in,
                      size_t in_len) {
  if (aead == NULL) {
    /* Handle the initial NULL cipher. */
    if (in_len > max_out) {
      OPENSSL_PUT_ERROR(SSL, SSL_AEAD_CTX_seal, SSL_R_BUFFER_TOO_SMALL);
      return 0;
    }
    memmove(out, in, in_len);
    *out_len = in_len;
    return 1;
  }

  uint8_t ad[13];
  size_t ad_len = ssl_aead_ctx_get_ad(aead, ad, type, wire_version, seqnum,
                                      in_len);

  /* Assemble the nonce. */
  uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH];
  size_t nonce_len = 0;
  memcpy(nonce, aead->fixed_nonce, aead->fixed_nonce_len);
  nonce_len += aead->fixed_nonce_len;
  if (aead->random_variable_nonce) {
    assert(aead->variable_nonce_included_in_record);
    if (!RAND_bytes(nonce + nonce_len, aead->variable_nonce_len)) {
      return 0;
    }
  } else {
    /* When sending we use the sequence number as the variable part of the
     * nonce. */
    assert(aead->variable_nonce_len == 8);
    memcpy(nonce + nonce_len, ad, aead->variable_nonce_len);
  }
  nonce_len += aead->variable_nonce_len;

  /* Emit the variable nonce if included in the record. */
  size_t extra_len = 0;
  if (aead->variable_nonce_included_in_record) {
    if (max_out < aead->variable_nonce_len) {
      OPENSSL_PUT_ERROR(SSL, SSL_AEAD_CTX_seal, SSL_R_BUFFER_TOO_SMALL);
      return 0;
    }
    if (out < in + in_len && in < out + aead->variable_nonce_len) {
      OPENSSL_PUT_ERROR(SSL, SSL_AEAD_CTX_seal, SSL_R_OUTPUT_ALIASES_INPUT);
      return 0;
    }
    memcpy(out, nonce + aead->fixed_nonce_len, aead->variable_nonce_len);
    extra_len = aead->variable_nonce_len;
    out += aead->variable_nonce_len;
    max_out -= aead->variable_nonce_len;
  }

  if (!EVP_AEAD_CTX_seal(&aead->ctx, out, out_len, max_out, nonce, nonce_len,
                         in, in_len, ad, ad_len)) {
    return 0;
  }
  *out_len += extra_len;
  return 1;
}
