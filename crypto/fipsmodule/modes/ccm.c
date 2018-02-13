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

#include <openssl/cpu.h>
#include <openssl/mem.h>

#include "../../internal.h"
#include "internal.h"


int CRYPTO_ccm128_init(CCM128_CONTEXT *ctx, unsigned M, unsigned L,
                       const void *key, block128_f block,
                       const uint8_t *nonce, size_t nonce_len,
                       const uint8_t *aad, size_t aad_len, size_t max_plain) {
  OPENSSL_memset(ctx, 0, sizeof(*ctx));
  ctx->block = block;
  ctx->nonce.c[0] = (uint8_t)((L - 1) & 7) | (uint8_t)(((M - 2) / 2) & 7) << 3;

  if (max_plain > (UINT64_C(1) << (15 - L))) {
    return 0;
  }

  for (size_t i = 0; i < 15; i++) {
    if (i < L) {
      ctx->nonce.c[15 - i] = (uint8_t)(max_plain >> (8 * i));
    } else {
      ctx->nonce.c[15 - i] = 0;
    }
  }

  OPENSSL_memcpy(&ctx->nonce.c[1], nonce, nonce_len);

  if (aad_len == 0) {
    ctx->nonce.c[0] &= ~0x40;  // Clear AAD Flag
    return 1;
  }

  ctx->nonce.c[0] |= 0x40;  // Set AAD Flag

  (*block)(ctx->nonce.c, ctx->cmac.c, key);
  ctx->blocks++;

  unsigned i;
  // Cast to u64 to avoid the compiler complaining about invalid shifts.
  uint64_t aad_len_u64 = aad_len;
  if (aad_len_u64 < 0x10000 - 0x100) {
    ctx->cmac.c[0] ^= (uint8_t)(aad_len >> 8);
    ctx->cmac.c[1] ^= (uint8_t)aad_len;
    i = 2;
  } else if (aad_len_u64 <= 0xffffffff) {
    ctx->cmac.c[0] ^= 0xff;
    ctx->cmac.c[1] ^= 0xfe;
    ctx->cmac.c[2] ^= (uint8_t)(aad_len >> 24);
    ctx->cmac.c[3] ^= (uint8_t)(aad_len >> 16);
    ctx->cmac.c[4] ^= (uint8_t)(aad_len >> 8);
    ctx->cmac.c[5] ^= (uint8_t)aad_len;
    i = 6;
  } else {
    ctx->cmac.c[0] ^= 0xff;
    ctx->cmac.c[1] ^= 0xff;
    ctx->cmac.c[2] ^= (uint8_t)(aad_len >> (56 % (sizeof(aad_len) * 8)));
    ctx->cmac.c[3] ^= (uint8_t)(aad_len >> (48 % (sizeof(aad_len) * 8)));
    ctx->cmac.c[4] ^= (uint8_t)(aad_len >> (40 % (sizeof(aad_len) * 8)));
    ctx->cmac.c[5] ^= (uint8_t)(aad_len >> (32 % (sizeof(aad_len) * 8)));
    ctx->cmac.c[6] ^= (uint8_t)(aad_len >> 24);
    ctx->cmac.c[7] ^= (uint8_t)(aad_len >> 16);
    ctx->cmac.c[8] ^= (uint8_t)(aad_len >> 8);
    ctx->cmac.c[9] ^= (uint8_t)aad_len;
    i = 10;
  }

  do {
    for (; i < 16 && aad_len; i++) {
      ctx->cmac.c[i] ^= *aad;
      aad++;
      aad_len--;
    }
    (*block)(ctx->cmac.c, ctx->cmac.c, key);
    ctx->blocks++;
    i = 0;
  } while (aad_len);

  return 1;
}

// counter part of nonce may not be larger than L*8 bits.
static void increment_ctr128(uint8_t counter[16]) {
  unsigned n = 8;

  counter += 8;
  do {
    --n;
      uint8_t c = counter[n];
    ++c;
    counter[n] = c;
    if (c) {
      return;
    }
  } while (n);
}

int CRYPTO_ccm128_encrypt(CCM128_CONTEXT *ctx, const void *key,
                          const uint8_t *in, uint8_t *out, size_t len) {
  block128_f block = ctx->block;
  uint8_t flags0 = ctx->nonce.c[0];
  if (!(flags0 & 0x40)) {
    (*block)(ctx->nonce.c, ctx->cmac.c, key);
    ctx->blocks++;
  }

  unsigned L = flags0 & 7;
  ctx->nonce.c[0] = L;

  size_t n = 0;
  for (size_t i = 15 - L; i < 15; ++i) {
    n |= ctx->nonce.c[i];
    ctx->nonce.c[i] = 0;
    n <<= 8;
  }
  n |= ctx->nonce.c[15];  // reconstructed length
  ctx->nonce.c[15] = 1;

  if (n != len) {
    return 0;  // length mismatch
  }

  ctx->blocks += ((len + 15) >> 3) | 1;
  if (ctx->blocks > (uint64_t)1 << 61) {
    return 0;  // too much data
  }

  union {
    uint64_t u[2];
    uint8_t c[16];
  } scratch;
  while (len >= 16) {
    union {
      uint64_t u[2];
      uint8_t c[16];
    } temp;

    OPENSSL_memcpy(temp.c, in, 16);
    ctx->cmac.u[0] ^= temp.u[0];
    ctx->cmac.u[1] ^= temp.u[1];
    (*block)(ctx->cmac.c, ctx->cmac.c, key);
    (*block)(ctx->nonce.c, scratch.c, key);
    increment_ctr128(ctx->nonce.c);
    temp.u[0] ^= scratch.u[0];
    temp.u[1] ^= scratch.u[1];
    OPENSSL_memcpy(out, temp.c, 16);

    in += 16;
    out += 16;
    len -= 16;
  }

  if (len) {
    for (size_t i = 0; i < len; ++i) {
      ctx->cmac.c[i] ^= in[i];
    }
    (*block)(ctx->cmac.c, ctx->cmac.c, key);
    (*block)(ctx->nonce.c, scratch.c, key);
    for (size_t i = 0; i < len; ++i) {
      out[i] = scratch.c[i] ^ in[i];
    }
  }

  for (size_t i = 15 - L; i < 16; ++i) {
    ctx->nonce.c[i] = 0;
  }

  (*block)(ctx->nonce.c, scratch.c, key);
  ctx->cmac.u[0] ^= scratch.u[0];
  ctx->cmac.u[1] ^= scratch.u[1];

  ctx->nonce.c[0] = flags0;

  return 1;
}

int CRYPTO_ccm128_decrypt(CCM128_CONTEXT *ctx, const void *key,
                          const unsigned char *in, unsigned char *out,
                          size_t len) {
  block128_f block = ctx->block;
  uint8_t flags0 = ctx->nonce.c[0];
  if (!(flags0 & 0x40)) {
    (*block)(ctx->nonce.c, ctx->cmac.c, key);
  }

  unsigned L = flags0 & 7;
  ctx->nonce.c[0] = L;

  size_t n = 0;
  for (size_t i = 15 - L; i < 15; ++i) {
    n |= ctx->nonce.c[i];
    ctx->nonce.c[i] = 0;
    n <<= 8;
  }
  n |= ctx->nonce.c[15];  // reconstructed length
  ctx->nonce.c[15] = 1;

  if (n != len) {
    return 0;
  }

  union {
    uint64_t u[2];
    uint8_t c[16];
  } scratch;
  while (len >= 16) {
    union {
      uint64_t u[2];
      uint8_t c[16];
    } temp;
    (*block)(ctx->nonce.c, scratch.c, key);
    increment_ctr128(ctx->nonce.c);
    OPENSSL_memcpy(temp.c, in, 16);
    ctx->cmac.u[0] ^= (scratch.u[0] ^= temp.u[0]);
    ctx->cmac.u[1] ^= (scratch.u[1] ^= temp.u[1]);
    OPENSSL_memcpy(out, scratch.c, 16);
    (*block)(ctx->cmac.c, ctx->cmac.c, key);

    in += 16;
    out += 16;
    len -= 16;
  }

  if (len) {
    (*block)(ctx->nonce.c, scratch.c, key);
    for (size_t i = 0; i < len; ++i) {
      ctx->cmac.c[i] ^= (out[i] = scratch.c[i] ^ in[i]);
    }
    (*block)(ctx->cmac.c, ctx->cmac.c, key);
  }

  for (size_t i = 15 - L; i < 16; ++i) {
    ctx->nonce.c[i] = 0;
  }

  (*block)(ctx->nonce.c, scratch.c, key);
  ctx->cmac.u[0] ^= scratch.u[0];
  ctx->cmac.u[1] ^= scratch.u[1];

  ctx->nonce.c[0] = flags0;

  return 1;
}

size_t CRYPTO_ccm128_tag(CCM128_CONTEXT *ctx, uint8_t *tag, size_t len) {
  OPENSSL_memcpy(tag, ctx->cmac.c, len);
  return len;
}
