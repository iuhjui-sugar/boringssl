/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
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
 */

#include <assert.h>
#include <string.h>

#include <openssl/mem.h>
#include <openssl/cpu.h>

#include "internal.h"
#include "../../internal.h"

void CRYPTO_ccm128_init(CCM128_CONTEXT *ctx, unsigned tag_len,
                        const void *aes_key, block128_f block) {
  OPENSSL_memset(ctx, 0, sizeof(*ctx));
  ctx->block = block;
  ctx->nonce.c[0] = (uint8_t)(((tag_len - 2) / 2) & 7) << 3;
}

int CRYPTO_ccm128_setiv(CCM128_CONTEXT *ctx, const void *key,
                        const uint8_t *nonce, size_t len, size_t mlen) {
  unsigned int L = 15 - len;
  ctx->nonce.c[0] |= (uint8_t)(L - 1) & 7;

  for (size_t indx = 0; indx < L; indx++) {
    ctx->nonce.c[15-indx] = (uint8_t)(mlen >> (8*indx));
  }

  for (size_t indx = L; indx < 15; indx++) {
    ctx->nonce.c[15-indx] = 0;
  }

  ctx->nonce.c[0] &= ~0x40; // Clear AAD Flag
  OPENSSL_memcpy(&ctx->nonce.c[1], nonce, len);

  return 1;
}

int CRYPTO_ccm128_aad(CCM128_CONTEXT *ctx, const void *key, const uint8_t *aad,
                      size_t len) {
  unsigned int i;
  block128_f block = ctx->block;

  if (len == 0) {
    return 0;
  }

  ctx->nonce.c[0] |= 0x40; // Set AAD Flag
  (*block)(ctx->nonce.c, ctx->cmac.c, key), ctx->blocks++;

  if (len < (0x10000 - 0x100)) {
    ctx->cmac.c[0] ^= (uint8_t)(len >> 8);
    ctx->cmac.c[1] ^= (uint8_t)len;
    i = 2;
  } else if (sizeof(len) == 8 && len >= (size_t)1
                                              << (32 % (sizeof(len) * 8))) {
    ctx->cmac.c[0] ^= 0xFF;
    ctx->cmac.c[1] ^= 0xFF;
    ctx->cmac.c[2] ^= (uint8_t)(len >> (56 % (sizeof(len) * 8)));
    ctx->cmac.c[3] ^= (uint8_t)(len >> (48 % (sizeof(len) * 8)));
    ctx->cmac.c[4] ^= (uint8_t)(len >> (40 % (sizeof(len) * 8)));
    ctx->cmac.c[5] ^= (uint8_t)(len >> (32 % (sizeof(len) * 8)));
    ctx->cmac.c[6] ^= (uint8_t)(len >> 24);
    ctx->cmac.c[7] ^= (uint8_t)(len >> 16);
    ctx->cmac.c[8] ^= (uint8_t)(len >> 8);
    ctx->cmac.c[9] ^= (uint8_t)len;
    i = 10;
  } else {
    ctx->cmac.c[0] ^= 0xFF;
    ctx->cmac.c[1] ^= 0xFE;
    ctx->cmac.c[2] ^= (uint8_t)(len >> 24);
    ctx->cmac.c[3] ^= (uint8_t)(len >> 16);
    ctx->cmac.c[4] ^= (uint8_t)(len >> 8);
    ctx->cmac.c[5] ^= (uint8_t)len;
    i = 6;
  }

  do {
    for (; i < 16 && len; ++i, ++aad, --len)
      ctx->cmac.c[i] ^= *aad;
    (*block)(ctx->cmac.c, ctx->cmac.c, key), ctx->blocks++;
    i = 0;
  } while (len);

  return 1;
}

static void increment_ctr128(uint8_t *counter) {
  int n = 16;
  uint8_t c;

  do {
    --n;
    c = counter[n];
    ++c;
    counter[n] = c;
    if (c) {
      return;
    }
  } while (n);
}

int CRYPTO_ccm128_encrypt(CCM128_CONTEXT *ctx, const void *key,
                          const uint8_t *in, uint8_t *out, size_t len) {
  size_t n;
  unsigned int i, L;
  unsigned char flags0 = ctx->nonce.c[0];
  block128_f block = ctx->block;
  union {
    uint64_t u[2];
    uint8_t c[16];
  } scratch;

  if (!(flags0 & 0x40))
    (*block)(ctx->nonce.c, ctx->cmac.c, key), ctx->blocks++;

  ctx->nonce.c[0] = L = flags0 & 7;
  for (n = 0, i = 15 - L; i < 15; ++i) {
    n |= ctx->nonce.c[i];
    ctx->nonce.c[i] = 0;
    n <<= 8;
  }
  n |= ctx->nonce.c[15]; // Reconstructed length
  ctx->nonce.c[15] = 1;

  if (n != len) {
    return 0; // Length mismatch
  }

  ctx->blocks += ((len + 15) >> 3) | 1;
  if (ctx->blocks > (uint64_t)1 << 61) {
    return 0; // too much data
  }

  while (len >= 16) {
#if defined(STRICT_ALIGNMENT)
    union {
      uint64_t u[2];
      uint8_t c[16];
    } temp;

    OPENSSL_memcpy(temp.c, in, 16);
    ctx->cmac.u[0] ^= temp.u[0];
    ctx->cmac.u[1] ^= temp.u[1];
#else
    ctx->cmac.u[0] ^= ((uint64_t *)in)[0];
    ctx->cmac.u[1] ^= ((uint64_t *)in)[1];
#endif
    (*block)(ctx->cmac.c, ctx->cmac.c, key);
    (*block)(ctx->nonce.c, scratch.c, key);
    increment_ctr128(ctx->nonce.c);
#if defined(STRICT_ALIGNMENT)
    temp.u[0] ^= scratch.u[0];
    temp.u[1] ^= scratch.u[1];
    OPENSSL_memcpy(out, temp.c, 16);
#else
    ((uint64_t *)out)[0] = scratch.u[0] ^ ((uint64_t *)in)[0];
    ((uint64_t *)out)[1] = scratch.u[1] ^ ((uint64_t *)in)[1];
#endif
    in += 16;
    out += 16;
    len -= 16;
  }

  if (len) {
    for (i = 0; i < len; ++i)
      ctx->cmac.c[i] ^= in[i];
    (*block)(ctx->cmac.c, ctx->cmac.c, key);
    (*block)(ctx->nonce.c, scratch.c, key);
    for (i = 0; i < len; ++i)
      out[i] = scratch.c[i] ^ in[i];
  }

  for (i = 15 - L; i < 16; ++i)
    ctx->nonce.c[i] = 0;

  (*block)(ctx->nonce.c, scratch.c, key);
  ctx->cmac.u[0] ^= scratch.u[0];
  ctx->cmac.u[1] ^= scratch.u[1];

  ctx->nonce.c[0] = flags0;

  return 1;
}

int CRYPTO_ccm128_decrypt(CCM128_CONTEXT *ctx, const void *key,
                          const unsigned char *in, unsigned char *out,
                          size_t len) {
  size_t n;
  unsigned int i, L;
  unsigned char flags0 = ctx->nonce.c[0];
  block128_f block = ctx->block;
  union {
    uint64_t u[2];
    uint8_t c[16];
  } scratch;

  if (!(flags0 & 0x40))
    (*block)(ctx->nonce.c, ctx->cmac.c, key);

  ctx->nonce.c[0] = L = flags0 & 7;
  for (n = 0, i = 15 - L; i < 15; ++i) {
    n |= ctx->nonce.c[i];
    ctx->nonce.c[i] = 0;
    n <<= 8;
  }
  n |= ctx->nonce.c[15]; /* reconstructed length */
  ctx->nonce.c[15] = 1;

  if (n != len) {
    return 0;
  }

  while (len >= 16) {
#if defined(STRICT_ALIGNMENT)
    union {
      uint64_t u[2];
      uint8_t c[16];
    } temp;
#endif
    (*block)(ctx->nonce.c, scratch.c, key);
    increment_ctr128(ctx->nonce.c);
#if defined(STRICT_ALIGNMENT)
    OPENSSL_memcpy(temp.c, in, 16);
    ctx->cmac.u[0] ^= (scratch.u[0] ^= temp.u[0]);
    ctx->cmac.u[1] ^= (scratch.u[1] ^= temp.u[1]);
    OPENSSL_memcpy(out, scratch.c, 16);
#else
    ctx->cmac.u[0] ^= (((uint64_t *)out)[0] = scratch.u[0] ^ ((uint64_t *)in)[0]);
    ctx->cmac.u[1] ^= (((uint64_t *)out)[1] = scratch.u[1] ^ ((uint64_t *)in)[1]);
#endif
    (*block)(ctx->cmac.c, ctx->cmac.c, key);

    in += 16;
    out += 16;
    len -= 16;
  }

  if (len) {
    (*block)(ctx->nonce.c, scratch.c, key);
    for (i = 0; i < len; ++i)
      ctx->cmac.c[i] ^= (out[i] = scratch.c[i] ^ in[i]);
    (*block)(ctx->cmac.c, ctx->cmac.c, key);
  }

  for (i = 15 - L; i < 16; ++i)
    ctx->nonce.c[i] = 0;

  (*block)(ctx->nonce.c, scratch.c, key);
  ctx->cmac.u[0] ^= scratch.u[0];
  ctx->cmac.u[1] ^= scratch.u[1];

  ctx->nonce.c[0] = flags0;

  return 1;
}

size_t CRYPTO_ccm128_tag(CCM128_CONTEXT *ctx, uint8_t *tag, size_t len) {
  unsigned int M = (ctx->nonce.c[0] >> 3) & 7; // the M parameter
  M *= 2;
  M += 2;
  if (len < M)
    return 0;
  OPENSSL_memcpy(tag, ctx->cmac.c, M);
  return M;
}
