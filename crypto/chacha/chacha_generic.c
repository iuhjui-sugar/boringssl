/* Copyright (c) 2014, Google Inc.
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

/* Adapted from the public domain, estream code by D. Bernstein. */

#include <openssl/chacha.h>

#include <string.h>

#include <openssl/cpu.h>

/* sigma contains the ChaCha constants, which happen to be an ASCII string. */
static const uint8_t sigma[16] = { 'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
                                   '2', '-', 'b', 'y', 't', 'e', ' ', 'k' };

#define ROTATE(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define XOR(v, w) ((v) ^ (w))
#define PLUS(x, y) ((x) + (y))
#define PLUSONE(v) (PLUS((v), 1))

#define U32TO8_LITTLE(p, v)    \
  {                            \
    (p)[0] = (v >> 0) & 0xff;  \
    (p)[1] = (v >> 8) & 0xff;  \
    (p)[2] = (v >> 16) & 0xff; \
    (p)[3] = (v >> 24) & 0xff; \
  }

#define U8TO32_LITTLE(p)                              \
  (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | \
   ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))

/* QUARTERROUND updates a, b, c, d with a ChaCha "quarter" round. */
#define QUARTERROUND(a,b,c,d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

#if defined(__ARM_NEON__) ||          \
    !defined(OPENSSL_WINDOWS) && \
        (defined(OPENSSL_X86_64) || defined(OPENSSL_X86)) && defined(__SSE2__)
#define CHACHA20_HAS_COMPILER_VECTORIZED
/* Defined in chacha_vec.c */
void CRYPTO_chacha_20_compiler_vec(uint8_t *out, const uint8_t *in, size_t in_len,
                           const uint8_t key[32], const uint8_t nonce[8],
                           size_t counter);
#endif

#if defined(OPENSSL_NO_ASM) \
    || defined(OPENSSL_ARM) \
    || !defined(CHACHA20_HAS_COMPILER_VECTORIZED)
/* chacha_core performs 20 rounds of ChaCha on the input words in
 * |input| and writes the 64 output bytes to |output|. */
static void chacha_core(uint8_t output[64], const uint32_t input[16]) {
  uint32_t x[16];
  int i;

  memcpy(x, input, sizeof(uint32_t) * 16);
  for (i = 20; i > 0; i -= 2) {
    QUARTERROUND(0, 4, 8, 12)
    QUARTERROUND(1, 5, 9, 13)
    QUARTERROUND(2, 6, 10, 14)
    QUARTERROUND(3, 7, 11, 15)
    QUARTERROUND(0, 5, 10, 15)
    QUARTERROUND(1, 6, 11, 12)
    QUARTERROUND(2, 7, 8, 13)
    QUARTERROUND(3, 4, 9, 14)
  }

  for (i = 0; i < 16; ++i) {
    x[i] = PLUS(x[i], input[i]);
  }
  for (i = 0; i < 16; ++i) {
    U32TO8_LITTLE(output + 4 * i, x[i]);
  }
}

static void chacha_20_simple(uint8_t *out, const uint8_t *in, size_t in_len,
                             const uint8_t key[32], const uint8_t nonce[8],
                             size_t counter) {
  uint32_t input[16];
  uint8_t buf[64];
  size_t todo, i;

  input[0] = U8TO32_LITTLE(sigma + 0);
  input[1] = U8TO32_LITTLE(sigma + 4);
  input[2] = U8TO32_LITTLE(sigma + 8);
  input[3] = U8TO32_LITTLE(sigma + 12);

  input[4] = U8TO32_LITTLE(key + 0);
  input[5] = U8TO32_LITTLE(key + 4);
  input[6] = U8TO32_LITTLE(key + 8);
  input[7] = U8TO32_LITTLE(key + 12);

  input[8] = U8TO32_LITTLE(key + 16);
  input[9] = U8TO32_LITTLE(key + 20);
  input[10] = U8TO32_LITTLE(key + 24);
  input[11] = U8TO32_LITTLE(key + 28);

  input[12] = counter;
  input[13] = ((uint64_t)counter) >> 32;
  input[14] = U8TO32_LITTLE(nonce + 0);
  input[15] = U8TO32_LITTLE(nonce + 4);

  while (in_len > 0) {
    todo = sizeof(buf);
    if (in_len < todo) {
      todo = in_len;
    }

    chacha_core(buf, input);
    for (i = 0; i < todo; i++) {
      out[i] = in[i] ^ buf[i];
    }

    out += todo;
    in += todo;
    in_len -= todo;

    input[12]++;
    if (input[12] == 0) {
      input[13]++;
    }
  }
}
#endif  /* OPENSSL_NO_ASM || OPENSSL_ARM || !CHACHA20_HAS_COMPILER_VECTORIZED */

#if defined(OPENSSL_X86_64) && !defined(OPENSSL_NO_ASM)
#define CHACHA20_HAS_AVX
void chacha_20_core_avx(uint8_t *out, const uint8_t *in, size_t in_len,
                      const uint8_t key[32], const uint8_t nonce[8],
                      size_t counter);
void chacha_20_core_avx2(uint8_t *out, const uint8_t *in, size_t in_len,
                      const uint8_t key[32], const uint8_t nonce[8],
                      size_t counter);

typedef void (*chacha_core_function)(uint8_t*, const uint8_t*, size_t,
                                     const uint8_t[32], const uint8_t[8], size_t);

void CRYPTO_chacha_20_avx_or_avx2(uint8_t *out, const uint8_t *in, size_t in_len,
                      const uint8_t key[32], const uint8_t nonce[8],
                      size_t counter) {
  uint8_t buffer[256];
  size_t todo, buffer_size, counter_mask;
  chacha_core_function core_function;

  if (CRYPTO_has_AVX2()) {
    buffer_size = 128;
    counter_mask = -2;
    core_function = chacha_20_core_avx2;
  } else {
    buffer_size = 64;
    counter_mask = -1;
    core_function = chacha_20_core_avx;
  }

  core_function(out, in, in_len, key, nonce, counter);
  todo = in_len & (~(-buffer_size));
  if (todo) {
    out += in_len&(-buffer_size);
    in += in_len&(-buffer_size);
    counter += (in_len/64) & counter_mask;
    memcpy(buffer, in, todo);
    core_function(buffer, buffer, buffer_size, key, nonce, counter);
    memcpy(out, buffer, todo);
    memset(buffer, 0, buffer_size);
  }
}
#endif

void CRYPTO_chacha_20(uint8_t *out, const uint8_t *in, size_t in_len,
                      const uint8_t key[32], const uint8_t nonce[8],
                      size_t counter) {
#ifdef CHACHA20_HAS_AVX
  if (CRYPTO_has_AVX()) {
    CRYPTO_chacha_20_avx_or_avx2(out, in, in_len, key, nonce, counter);
    return;
  }
#endif

#if defined(OPENSSL_ARM) && !defined(OPENSSL_NO_ASM)
  if (CRYPTO_is_NEON_capable()) {
    CRYPTO_chacha_20_compiler_vec(out, in, in_len, key, nonce, counter);
  } else {
    chacha_20_simple(out, in, in_len, key, nonce, counter);
  }
#elif defined(CHACHA20_HAS_COMPILER_VECTORIZED) && !defined(OPENSSL_NO_ASM)
  CRYPTO_chacha_20_compiler_vec(out, in, in_len, key, nonce, counter);
#else
  chacha_20_simple(out, in, in_len, key, nonce, counter);
#endif
}
