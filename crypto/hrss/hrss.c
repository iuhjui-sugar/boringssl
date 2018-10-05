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

#include <openssl/hrss.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/cpu.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/sha.h>

#if defined(OPENSSL_X86_64)
#define HRSS_ASM
#endif

#if defined(OPENSSL_AARCH64)
#include <arm_neon.h>
#endif

#include "../internal.h"

// This is an implementation of [HRSS], but with a KEM transformation based on
// [SXY]. The primary references are:

// HRSS: https://eprint.iacr.org/2017/1005
// HRSSNIST:
// https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/round-1/submissions/NTRU_HRSS_KEM.zip
// SXY: https://eprint.iacr.org/2017/1005.pdf
// NTRUTN14:
// https://assets.onboardsecurity.com/static/downloads/NTRU/resources/NTRUTech014.pdf

// Polynomials in these scheme have N terms.
#define N 701

// Underlying data types and arithmetic operations.
// ------------------------------------------------

// Binary polynomials.

// poly2 represents a degree-N polynomial over GF(2). The words are in little-
// endian order, i.e. the coefficient of x^0 is the LSB of the first word. The
// final word is only partially used since N is not a multiple of the word size.

typedef uintptr_t word_t;
#define BITS_PER_WORD (sizeof(word_t) * 8)
#define WORDS_PER_POLY ((N + BITS_PER_WORD - 1) / BITS_PER_WORD)
#define BITS_IN_LAST_WORD (N % BITS_PER_WORD)

struct poly2 {
  word_t v[WORDS_PER_POLY];
};

static void poly2_zero(struct poly2 *p) {
  OPENSSL_memset(&p->v[0], 0, sizeof(word_t) * WORDS_PER_POLY);
}

// poly2_cmov sets |out| to |in| iff |mov| is all ones.
static void poly2_cmov(struct poly2 *out, const struct poly2 *in,
                       crypto_word_t mov) {
  for (size_t i = 0; i < WORDS_PER_POLY; i++) {
    out->v[i] = (out->v[i] & ~mov) | (in->v[i] & mov);
  }
}

// poly2_rotr_words performs a right-rotate on |in|, writing the result to
// |out|. The shift count, |bits|, must be a multiple of the word size.
static void poly2_rotr_words(struct poly2 *out, const struct poly2 *in,
                             size_t bits) {
  assert(bits >= BITS_PER_WORD && bits % BITS_PER_WORD == 0);
  assert(out != in);

  const size_t start = bits / BITS_PER_WORD;
  const size_t n = (N - bits) / BITS_PER_WORD;

  // The rotate is by a whole number of words so the first few words are easy:
  // just move them down.
  for (size_t i = 0; i < n; i++) {
    out->v[i] = in->v[start + i];
  }

  // Since the last word is only partially filled, however, the remainder needs
  // shifting and merging of words to take care of that.
  word_t carry = in->v[WORDS_PER_POLY - 1];

  for (size_t i = 0; i < start; i++) {
    out->v[n + i] = carry | in->v[i] << BITS_IN_LAST_WORD;
    carry = in->v[i] >> (BITS_PER_WORD - BITS_IN_LAST_WORD);
  }

  out->v[WORDS_PER_POLY - 1] = carry;
}

// poly2_rotr_bits performs a right-rotate on |in|, writing the result to |out|.
// The shift count, |bits|, must be less than the size of a word.
static void poly2_rotr_bits(struct poly2 *out, const struct poly2 *in,
                            size_t bits) {
  assert(bits < BITS_PER_WORD);
  assert(out != in);

  word_t carry = in->v[WORDS_PER_POLY - 1] << (BITS_PER_WORD - bits);

  for (size_t i = WORDS_PER_POLY - 2; i < WORDS_PER_POLY; i--) {
    out->v[i] = carry | in->v[i] >> bits;
    carry = in->v[i] << (BITS_PER_WORD - bits);
  }

  out->v[WORDS_PER_POLY - 1] = carry >> (BITS_PER_WORD - BITS_IN_LAST_WORD) |
                               in->v[WORDS_PER_POLY - 1] >> bits;
}

// poly2_rotr_consttime right-rotates |p| by |bits| in constant-time.
static void poly2_rotr_consttime(struct poly2 *p, size_t bits) {
  assert(bits <= N);

  // Constant-time rotation is implemented by calculating the rotations of
  // powers-of-two bits and throwing away the unneeded values. 2^9 (i.e. 512) is
  // the largest power-of-two shift that we need to consider because 2^10 > N.
  size_t shift = 9;
  struct poly2 shifted;

  for (; (UINT64_C(1) << shift) >= BITS_PER_WORD; shift--) {
    poly2_rotr_words(&shifted, p, UINT64_C(1) << shift);
    poly2_cmov(p, &shifted, constant_time_eq_w(1 & (bits >> shift), 1));
  }

  for (; shift < 9; shift--) {
    poly2_rotr_bits(&shifted, p, UINT64_C(1) << shift);
    poly2_cmov(p, &shifted, constant_time_eq_w(1 & (bits >> shift), 1));
  }
}

// poly2_cswap exchanges the values of |a| and |b| if |swap| is all ones.
static void poly2_cswap(struct poly2 *a, struct poly2 *b, crypto_word_t swap) {
  for (size_t i = 0; i < WORDS_PER_POLY; i++) {
    const word_t sum = swap & (a->v[i] ^ b->v[i]);
    a->v[i] ^= sum;
    b->v[i] ^= sum;
  }
}

// poly2_fmadd sets |out| to |out| + |in| * m, where m is either zero or one.
static void poly2_fmadd(struct poly2 *out, const struct poly2 *in, word_t m) {
  m = ~(m - 1);

  for (size_t i = 0; i < WORDS_PER_POLY; i++) {
    out->v[i] ^= in->v[i] & m;
  }
}

// poly2_lshift1 left-shifts |p| by one bit.
static void poly2_lshift1(struct poly2 *p) {
  word_t carry = 0;
  for (size_t i = 0; i < WORDS_PER_POLY; i++) {
    const word_t next_carry = p->v[i] >> (BITS_PER_WORD - 1);
    p->v[i] <<= 1;
    p->v[i] |= carry;
    carry = next_carry;
  }
}

// poly2_rshift1 right-shifts |p| by one bit.
static void poly2_rshift1(struct poly2 *p) {
  word_t carry = 0;
  for (size_t i = WORDS_PER_POLY - 1; i < WORDS_PER_POLY; i--) {
    const word_t next_carry = p->v[i] & 1;
    p->v[i] >>= 1;
    p->v[i] |= carry << (BITS_PER_WORD - 1);
    carry = next_carry;
  }
}

// Ternary polynomials.

// poly3 represents a degree-N polynomial over GF(3). Each coefficient is
// bitsliced across the |s| and |a| arrays, like this:
//
//   s  |  a  | value
//  -----------------
//   0  |  0  | 0
//   0  |  1  | 1
//   1  |  0  | 2 (aka -1)
//   1  |  1  | <invalid>
//
// Once bitsliced as such, the following circuits can be used to implement
// addition and multiplication mod 3:
//
//   (s3, a3) = (s1, a1) × (s2, a2)
//   s3 = (s2 ∧ a1) ⊕ (s1 ∧ a2)
//   a3 = (s1 ∧ s2) ⊕ (a1 ∧ a2)
//
//   (s3, a3) = (s1, a1) + (s2, a2)
//   t1 = ~(s1 ∨ a1)
//   t2 = ~(s2 ∨ a2)
//   s3 = (a1 ∧ a2) ⊕ (t1 ∧ s2) ⊕ (t2 ∧ s1)
//   a3 = (s1 ∧ s2) ⊕ (t1 ∧ a2) ⊕ (t2 ∧ a1)
struct poly3 {
  struct poly2 s, a;
};

OPENSSL_UNUSED static void poly3_print(const struct poly3 *in) {
  struct poly3 p;
  OPENSSL_memcpy(&p, in, sizeof(p));
  p.s.v[WORDS_PER_POLY - 1] &= ((word_t)1 << BITS_IN_LAST_WORD) - 1;
  p.a.v[WORDS_PER_POLY - 1] &= ((word_t)1 << BITS_IN_LAST_WORD) - 1;

  printf("{[");
  for (unsigned i = 0; i < WORDS_PER_POLY; i++) {
    if (i) {
      printf(" ");
    }
    printf("%zx", p.s.v[i]);
  }
  printf("] [");
  for (unsigned i = 0; i < WORDS_PER_POLY; i++) {
    if (i) {
      printf(" ");
    }
    printf("%zx", p.a.v[i]);
  }
  printf("]}\n");
}

static void poly3_zero(struct poly3 *p) {
  poly2_zero(&p->s);
  poly2_zero(&p->a);
}

// lsb_to_all replicates the least-significant bit of |v| to all bits of the
// word. This is used in bit-slicing operations to make a vector from a fixed
// value.
static word_t lsb_to_all(word_t v) {
  return ~((v & 1) - 1);
}

// poly3_mul_const sets |p| to |p|×m, where m  = (ms, ma).
static void poly3_mul_const(struct poly3 *p, word_t ms, word_t ma) {
  ms = lsb_to_all(ms);
  ma = lsb_to_all(ma);

  for (size_t i = 0; i < WORDS_PER_POLY; i++) {
    const word_t s = p->s.v[i];
    const word_t a = p->a.v[i];
    p->s.v[i] = (s & ma) ^ (ms & a);
    p->a.v[i] = (ms & s) ^ (ma & a);
  }
}

// poly3_rotr_consttime right-rotates |p| by |bits| in constant-time.
static void poly3_rotr_consttime(struct poly3 *p, size_t bits) {
  assert(bits <= N);
  poly2_rotr_consttime(&p->s, bits);
  poly2_rotr_consttime(&p->a, bits);
}

// poly3_fmadd sets |out| to |out| + |in|×m, where m is (ms, ma).
static void poly3_fmadd(struct poly3 *restrict out,
                        const struct poly3 *restrict in, word_t ms, word_t ma) {
  ms = lsb_to_all(ms);
  ma = lsb_to_all(ma);

  // (See the multiplication and addition circuits given above.)
  for (size_t i = 0; i < WORDS_PER_POLY; i++) {
    const word_t s = in->s.v[i];
    const word_t a = in->a.v[i];
    const word_t product_s = (s & ma) ^ (ms & a);
    const word_t product_a = (ms & s) ^ (ma & a);
    const word_t orig_s = out->s.v[i];
    const word_t orig_a = out->a.v[i];
    const word_t t1 = ~(orig_s | orig_a);
    const word_t t2 = ~(product_s | product_a);
    out->s.v[i] = (orig_a & product_a) ^ (t1 & product_s) ^ (t2 & orig_s);
    out->a.v[i] = (orig_s & product_s) ^ (t1 & product_a) ^ (t2 & orig_a);
  }
}

// final_bit_to_all replicates the bit in the final position of the last word to
// all the bits in the word.
static word_t final_bit_to_all(word_t v) {
  return (uintptr_t)((intptr_t)(v << (BITS_PER_WORD - BITS_IN_LAST_WORD)) >>
                     (BITS_PER_WORD - 1));
}

// poly3_mod_phiN reduces |p| by Φ(N).
static void poly3_mod_phiN(struct poly3 *p) {
  // In order to reduce by Φ(N) we subtract by the value of the greatest
  // coefficient. That's the same as adding the negative of its value. The
  // negative of (s, a) is (a, s), so the arguments are swapped in the following
  // two lines.
  const word_t factor_s = final_bit_to_all(p->a.v[WORDS_PER_POLY - 1]);
  const word_t factor_a = final_bit_to_all(p->s.v[WORDS_PER_POLY - 1]);
  const word_t t2 = ~(factor_s | factor_a);

  for (size_t i = 0; i < WORDS_PER_POLY; i++) {
    const word_t s = p->s.v[i];
    const word_t a = p->a.v[i];
    const word_t t1 = ~(s | a);
    p->s.v[i] = (a & factor_a) ^ (t1 & factor_s) ^ (t2 & s);
    p->a.v[i] = (s & factor_s) ^ (t1 & factor_a) ^ (t2 & a);
  }
}

static void poly3_cswap(struct poly3 *a, struct poly3 *b, crypto_word_t swap) {
  poly2_cswap(&a->s, &b->s, swap);
  poly2_cswap(&a->a, &b->a, swap);
}

static void poly3_lshift1(struct poly3 *p) {
  poly2_lshift1(&p->s);
  poly2_lshift1(&p->a);
}

static void poly3_rshift1(struct poly3 *p) {
  poly2_rshift1(&p->s);
  poly2_rshift1(&p->a);
}

// poly3_mulx sets |p| to x×|p| mod (x^n - 1). In practice, this is a left-
// rotate by one bit.
static void poly3_mulx(struct poly3 *p) {
  word_t carry_s = (p->s.v[WORDS_PER_POLY - 1] >> (BITS_IN_LAST_WORD - 1)) & 1;
  word_t carry_a = (p->a.v[WORDS_PER_POLY - 1] >> (BITS_IN_LAST_WORD - 1)) & 1;

  for (size_t i = 0; i < WORDS_PER_POLY; i++) {
    const word_t next_carry_s = p->s.v[i] >> (BITS_PER_WORD - 1);
    const word_t next_carry_a = p->a.v[i] >> (BITS_PER_WORD - 1);
    p->s.v[i] <<= 1;
    p->a.v[i] <<= 1;
    p->s.v[i] |= carry_s;
    p->a.v[i] |= carry_a;
    carry_s = next_carry_s;
    carry_a = next_carry_a;
  }
}

// poly3_mul sets |*out| to |x|×|y| mod Φ(N).
static void poly3_mul(struct poly3 *out, const struct poly3 *x,
                      const struct poly3 *y_in) {
  assert(out != x);

  struct poly3 y;
  OPENSSL_memcpy(&y, y_in, sizeof(y));
  poly3_zero(out);

  // (𝑥^n - 1) is a multiple of Φ(N) so we can work mod (𝑥^n - 1) here and
  // reduce mod Φ(N) afterwards.
  size_t word_i = 0;
  unsigned shift = 0;
  word_t sw = x->s.v[0];
  word_t aw = x->a.v[0];

  for (size_t i = 0; i < N; i++) {
    poly3_fmadd(out, &y, sw, aw);
    sw >>= 1;
    aw >>= 1;
    shift++;
    if (shift == BITS_PER_WORD) {
      word_i++;
      sw = x->s.v[word_i];
      aw = x->a.v[word_i];
      shift = 0;
    }
    poly3_mulx(&y);
  }
  poly3_mod_phiN(out);
}

// poly3_invert sets |*out| to |in|^-1, i.e. such that |out|×|in| == 1.
static void poly3_invert(struct poly3 *out, const struct poly3 *in) {
  // This algorithm follows algorithm 10 in the paper. (Although, in contrast to
  // the paper, k should start at zero, not one, and the rotation count is needs
  // to handle trailing zero coefficients.) The best explanation for why it
  // works is in the "Why it works" section of [NTRUTN14].

  struct poly3 c, f, g;
  OPENSSL_memcpy(&f, in, sizeof(f));

  // Set g to all ones.
  OPENSSL_memset(&g.s, 0, sizeof(struct poly2));
  OPENSSL_memset(&g.a, 0xff, sizeof(struct poly2));
  g.a.v[WORDS_PER_POLY - 1] >>= BITS_PER_WORD - BITS_IN_LAST_WORD;

  struct poly3 *b = out;
  poly3_zero(b);
  poly3_zero(&c);
  // Set b to one.
  b->a.v[0] = 1;

  crypto_word_t k = 0, deg_f = N - 1, deg_g = N - 1, rotation = 0;
  word_t f0s = 0, f0a = 0;
  crypto_word_t still_going = CONSTTIME_TRUE_W;

  for (unsigned i = 0; i < 2 * (N - 1) - 1; i++) {
    const word_t s_a =
        1 & still_going & ((f.a.v[0] & g.s.v[0]) ^ (f.s.v[0] & g.a.v[0]));
    const word_t s_s =
        1 & still_going & ((f.a.v[0] & g.a.v[0]) ^ (f.s.v[0] & g.s.v[0]));
    const crypto_word_t should_swap =
        ~constant_time_is_zero_w(s_s | s_a) & constant_time_lt_w(deg_f, deg_g);
    poly3_cswap(&f, &g, should_swap);
    poly3_cswap(b, &c, should_swap);

    const crypto_word_t deg_sum = should_swap & (deg_f ^ deg_g);
    deg_f ^= deg_sum;
    deg_g ^= deg_sum;

    poly3_fmadd(&f, &g, s_s, s_a);
    poly3_fmadd(b, &c, s_s, s_a);
    poly3_rshift1(&f);
    poly3_lshift1(&c);

    deg_f--;
    k += 1 & still_going;
    const crypto_word_t f0_is_zero = constant_time_is_zero_w(f.s.v[0] & 1) &
                                     constant_time_is_zero_w(f.a.v[0] & 1);
    rotation = constant_time_select_w(still_going & ~f0_is_zero, k, rotation);
    f0s = constant_time_select_w(still_going & ~f0_is_zero, f.s.v[0], f0s);
    f0a = constant_time_select_w(still_going & ~f0_is_zero, f.a.v[0], f0a);
    still_going = ~constant_time_is_zero_w(deg_f);
  }

  rotation -= N & constant_time_lt_w(N, rotation);
  poly3_rotr_consttime(out, rotation);
  poly3_mul_const(out, f0s, f0a);
  poly3_mod_phiN(out);
}

// Polynomials in Q.

// Coefficients are reduced mod Q. (Q is clearly not prime, therefore the
// coefficients do not form a field.)
#define Q 8192

// poly represents a polynomial with coefficients mod Q. Note that, while Q is a
// power of two, this does not operate in GF(Q). That would be a binary field
// but this is simply mod Q. Thus the coefficients are not a field.
//
// Coefficients are ordered little-endian, thus the coefficient of x^0 is the
// first element of the array.
struct poly {
#if defined(OPENSSL_AARCH64) || defined(OPENSSL_ARM)
  alignas(16)
#endif
  uint16_t v[N+3];
};

OPENSSL_UNUSED static void poly_print(const struct poly *p) {
  printf("[");
  for (unsigned i = 0; i < N; i++) {
    if (i) {
      printf(" ");
    }
    printf("%d", p->v[i]);
  }
  printf("]\n");
}

OPENSSL_UNUSED static void hexdump(const void *void_in, size_t len) {
  const uint8_t *in = (const uint8_t *) void_in;
  for (size_t i = 0; i < len; i++) {
    printf("%02x", in[i]);
  }
  printf("\n");
}

#if defined(OPENSSL_AARCH64)

// kVecsPerPoly is the number of 128-bit NEON vectors needed to represent a
// polynomial.
#define VECS_PER_POLY ((N + 7) / 8)

void poly_mul_noasm_aarch64_aux(uint16x8_t *restrict out,
                                       uint16x8_t *restrict scratch,
                                       const uint16x8_t *a, const uint16x8_t *b,
                                       size_t n);

void poly_mul_noasm_aarch64_aux(uint16x8_t *restrict out,
                                       uint16x8_t *restrict scratch,
                                       const uint16x8_t *a, const uint16x8_t *b,
                                       size_t n) {
  assert(n != 1);

  if (n == 2) {
    uint16x8_t result[4];
    const uint16x8_t zero = {0};
    uint16x8_t vec_a[3];
    vec_a[0] = a[0];
    vec_a[1] = a[1];
    vec_a[2] = zero;

    const uint16_t *b_words = (const uint16_t *)b;
    result[0] = vmulq_n_u16(a[0], b_words[0]);
    result[1] = vmulq_n_u16(a[1], b_words[0]);

#define BLOCK_PRE(x, y)                                   \
  result[x + 0] = vmlaq_n_u16(result[x + 0], vec_a[0], b_words[y]); \
  result[x + 1] = vmulq_n_u16(vec_a[1], b_words[y]);

    BLOCK_PRE(1, 8);

    result[3] = zero;

#define ROTATE_VEC_A                           \
  vec_a[2] = vextq_u16(vec_a[1], vec_a[2], 7); \
  vec_a[1] = vextq_u16(vec_a[0], vec_a[1], 7); \
  vec_a[0] = vextq_u16(zero, vec_a[0], 7);

    ROTATE_VEC_A;

#define BLOCK(x, y)                                                 \
  result[x + 0] = vmlaq_n_u16(result[x + 0], vec_a[0], b_words[y]); \
  result[x + 1] = vmlaq_n_u16(result[x + 1], vec_a[1], b_words[y]); \
  result[x + 2] = vmlaq_n_u16(result[x + 2], vec_a[2], b_words[y]);

    BLOCK(0, 1);
    BLOCK(1, 9);

    ROTATE_VEC_A;

    BLOCK(0, 2);
    BLOCK(1, 10);

    ROTATE_VEC_A;

    BLOCK(0, 3);
    BLOCK(1, 11);

    ROTATE_VEC_A;

    BLOCK(0, 4);
    BLOCK(1, 12);

    ROTATE_VEC_A;

    BLOCK(0, 5);
    BLOCK(1, 13);

    ROTATE_VEC_A;

    BLOCK(0, 6);
    BLOCK(1, 14);

    ROTATE_VEC_A;

    BLOCK(0, 7);
    BLOCK(1, 15);

#undef BLOCK
#undef BLOCK_PRE
#undef ROTATE_VEC_A

    memcpy(out, result, sizeof(result));

    return;
  }

  if (n == 3) {
    uint16x8_t result[6];
    const uint16x8_t zero = {0};
    uint16x8_t vec_a[4];
    vec_a[0] = a[0];
    vec_a[1] = a[1];
    vec_a[2] = a[2];
    vec_a[3] = zero;

    const uint16_t *b_words = (const uint16_t *)b;
    result[0] = vmulq_n_u16(a[0], b_words[0]);
    result[1] = vmulq_n_u16(a[1], b_words[0]);
    result[2] = vmulq_n_u16(a[2], b_words[0]);

#define BLOCK_PRE(x, y)                                   \
  result[x + 0] = vmlaq_n_u16(result[x + 0], vec_a[0], b_words[y]); \
  result[x + 1] = vmlaq_n_u16(result[x + 1], vec_a[1], b_words[y]); \
  result[x + 2] = vmulq_n_u16(vec_a[2], b_words[y]);

    BLOCK_PRE(1, 8);
    BLOCK_PRE(2, 16);

    result[5] = zero;

#define ROTATE_VEC_A                           \
  vec_a[3] = vextq_u16(vec_a[2], vec_a[3], 7); \
  vec_a[2] = vextq_u16(vec_a[1], vec_a[2], 7); \
  vec_a[1] = vextq_u16(vec_a[0], vec_a[1], 7); \
  vec_a[0] = vextq_u16(zero, vec_a[0], 7);

    ROTATE_VEC_A;

#define BLOCK(x, y)                                           \
  result[x + 0] = vmlaq_n_u16(result[x + 0], vec_a[0], b_words[y]); \
  result[x + 1] = vmlaq_n_u16(result[x + 1], vec_a[1], b_words[y]); \
  result[x + 2] = vmlaq_n_u16(result[x + 2], vec_a[2], b_words[y]); \
  result[x + 3] = vmlaq_n_u16(result[x + 3], vec_a[3], b_words[y]);

    BLOCK(0, 1);
    BLOCK(1, 9);
    BLOCK(2, 17);

    ROTATE_VEC_A;

    BLOCK(0, 2);
    BLOCK(1, 10);
    BLOCK(2, 18);

    ROTATE_VEC_A;

    BLOCK(0, 3);
    BLOCK(1, 11);
    BLOCK(2, 19);

    ROTATE_VEC_A;

    BLOCK(0, 4);
    BLOCK(1, 12);
    BLOCK(2, 20);

    ROTATE_VEC_A;

    BLOCK(0, 5);
    BLOCK(1, 13);
    BLOCK(2, 21);

    ROTATE_VEC_A;

    BLOCK(0, 6);
    BLOCK(1, 14);
    BLOCK(2, 22);

    ROTATE_VEC_A;

    BLOCK(0, 7);
    BLOCK(1, 15);
    BLOCK(2, 23);

#undef BLOCK
#undef BLOCK_PRE
#undef ROTATE_VEC_A

    memcpy(out, result, sizeof(result));

    return;
  }

  // Karatsuba multiplication.
  // https://en.wikipedia.org/wiki/Karatsuba_algorithm

  // When |n| is odd, the two "halves" will have different lengths. The first is
  // always the smaller.
  const size_t low_len = n / 2;
  const size_t high_len = n - low_len;
  const uint16x8_t *a_high = &a[low_len];
  const uint16x8_t *b_high = &b[low_len];

  // Store a_1 + a_0 in the first half of |out| and b_1 + b_0 in the second
  // half.
  for (size_t i = 0; i < low_len; i++) {
    out[i] = a_high[i] + a[i];
    out[high_len + i] = b_high[i] + b[i];
  }
  if (high_len != low_len) {
    out[low_len] = a_high[low_len];
    out[high_len + low_len] = b_high[low_len];
  }

  uint16x8_t *const child_scratch = &scratch[2 * high_len];
  // Calculate (a_1 + a_0) × (b_1 + b_0) and write to scratch buffer.
  poly_mul_noasm_aarch64_aux(scratch, child_scratch, out, &out[high_len],
                             high_len);
  // Calculate a_1 × b_1.
  poly_mul_noasm_aarch64_aux(&out[low_len * 2], child_scratch, a_high, b_high,
                             high_len);
  // Calculate a_0 × b_0.
  poly_mul_noasm_aarch64_aux(out, child_scratch, a, b, low_len);

  // Subtract those last two products from the first.
  for (size_t i = 0; i < low_len * 2; i++) {
    scratch[i] -= out[i] + out[low_len * 2 + i];
  }
  if (low_len != high_len) {
    scratch[low_len * 2] -= out[low_len * 4];
    scratch[low_len * 2 + 1] -= out[low_len * 4 + 1];
  }

  // Add the middle product into the output.
  for (size_t i = 0; i < high_len * 2; i++) {
    out[low_len + i] += scratch[i];
  }
}

void poly_mul_noasm(struct poly *out, const struct poly *x,
                           const struct poly *y);

// poly_mul_noasm sets |*out| to |x|×|y| mod (𝑥^n - 1).
void poly_mul_noasm(struct poly *out, const struct poly *x,
                           const struct poly *y) {
  OPENSSL_memset((uint16_t *)&x->v[N], 0, 3 * sizeof(uint16_t));
  OPENSSL_memset((uint16_t *)&y->v[N], 0, 3 * sizeof(uint16_t));

  static_assert(sizeof(out->v) == sizeof(uint16x8_t) * VECS_PER_POLY,
                "struct poly is the wrong size");
  static_assert(alignof(struct poly) == alignof(uint16x8_t),
                "struct poly has incorrect alignment");
  uint16x8_t prod[VECS_PER_POLY * 2];
  uint16x8_t scratch[VECS_PER_POLY * 3];
  poly_mul_noasm_aarch64_aux(prod, scratch, (const uint16x8_t *)x->v,
                             (const uint16x8_t *)y->v, VECS_PER_POLY);

  // |prod| needs to be reduced mod (𝑥^n - 1), which just involves adding the
  // upper-half to the lower-half. However, N is 701, which isn't a multiple of
  // the vector size, the upper-half vectors all have to be shifted before being
  // added to the lower-half.
  uint16x8_t *out_vecs = (uint16x8_t *)out->v;
  for (size_t i = 0; i < VECS_PER_POLY; i++) {
    const uint16x8_t v =
        vextq_u16(prod[VECS_PER_POLY - 1 + i], prod[VECS_PER_POLY + i], 5);
    out_vecs[i] = prod[i] + v;
  }

  OPENSSL_memset(&out->v[N], 0, 3 * sizeof(uint16_t));
}

#else

// poly_mul_aux writes the product of |a| and |b| to |out|, using |scratch| as
// scratch space. It'll use Karatsuba if the inputs are large enough to warrant
// it.
static void poly_mul_noasm_aux(uint16_t *out, uint16_t *scratch,
                               const uint16_t *a, size_t a_len,
                               const uint16_t *b, size_t b_len) {
  // The inputs need not be even in length, but the lengths must be equal.
  assert(a_len == b_len);

  static const size_t kSchoolbookLimit = 64;
  if (a_len < kSchoolbookLimit) {
    OPENSSL_memset(out, 0, sizeof(uint16_t) * a_len * 2);
    for (size_t i = 0; i < a_len; i++) {
      for (size_t j = 0; j < b_len; j++) {
        out[i + j] += a[i] * b[j];
      }
    }

    return;
  }

  // Karatsuba multiplication.
  // https://en.wikipedia.org/wiki/Karatsuba_algorithm

  // When |a_len| is odd, the two "halves" will have different lengths. The
  // first is always the smaller.
  const size_t low_len = a_len / 2;
  const size_t high_len = a_len - low_len;
  const uint16_t *const a_high = &a[low_len];
  const uint16_t *const b_high = &b[low_len];

  for (size_t i = 0; i < low_len; i++) {
    out[i] = a_high[i] + a[i];
    out[high_len + i] = b_high[i] + b[i];
  }
  if (high_len != low_len) {
    out[low_len] = a_high[low_len];
    out[high_len + low_len] = b_high[low_len];
  }

  uint16_t *const child_scratch = &scratch[2 * high_len];
  poly_mul_noasm_aux(scratch, child_scratch, out, high_len, &out[high_len],
                     high_len);
  poly_mul_noasm_aux(&out[low_len * 2], child_scratch, a_high, high_len, b_high,
                     high_len);
  poly_mul_noasm_aux(out, child_scratch, a, low_len, b, low_len);

  for (size_t i = 0; i < low_len * 2; i++) {
    scratch[i] -= out[i] + out[low_len * 2 + i];
  }
  if (low_len != high_len) {
    scratch[low_len * 2] -= out[low_len * 4];
  }

  for (size_t i = 0; i < high_len * 2; i++) {
    out[low_len + i] += scratch[i];
  }
}

// poly_mul_noasm sets |*out| to |x|×|y| mod (𝑥^n - 1).
static void poly_mul_noasm(struct poly *out, const struct poly *x,
                           const struct poly *y) {
  uint16_t prod[2 * N];
  uint16_t scratch[2 * N];
  poly_mul_noasm_aux(prod, scratch, x->v, N, y->v, N);

  for (size_t i = 0; i < N; i++) {
    out->v[i] = prod[i] + prod[i + N];
  }
}

#endif  // !AARCH64

#if defined(OPENSSL_X86_64) && !defined(OPENSSL_NO_ASM)

// poly_Rq_mul is defined in assembly.
extern void poly_Rq_mul(struct poly *r, const struct poly *a,
                        const struct poly *b);

static void poly_mul(struct poly *r, const struct poly *a,
                     const struct poly *b) {
  const int has_avx2 = (OPENSSL_ia32cap_get()[2] & (1 << 5)) != 0;
  if (has_avx2) {
    poly_Rq_mul(r, a, b);
  } else {
    poly_mul_noasm(r, a, b);
  }
}

#elif defined(OPENSSL_ARM) && !defined(OPENSSL_NO_ASM)

// poly_Rq_mul is defined in assembly.
extern void poly_Rq_mul(struct poly *r, const struct poly *a,
                        const struct poly *b);

static void poly_mul(struct poly *r, const struct poly *a,
                     const struct poly *b) {
  if (CRYPTO_is_NEON_capable()) {
    poly_Rq_mul(r, a, b);
  } else {
    poly_mul_noasm(r, a, b);
  }
}

#else

static void poly_mul(struct poly *r, const struct poly *a,
                     const struct poly *b) {
  poly_mul_noasm(r, a, b);
}

#endif  // HRSS_ASM

// poly_mul_x_minus_1 sets |p| to |p|×(𝑥 - 1) mod (𝑥^n - 1).
static void poly_mul_x_minus_1(struct poly *p) {
  // Multiplying by (𝑥 - 1) means negating each coefficient and adding in
  // the value of the previous one.
  const uint16_t orig_final_coefficient = p->v[N - 1];

  for (size_t i = N - 1; i > 0; i--) {
    p->v[i] = p->v[i - 1] - p->v[i];
  }
  p->v[0] = orig_final_coefficient - p->v[0];
}

// poly_mod_phiN sets |p| to |p| mod Φ(N).
static void poly_mod_phiN(struct poly *p) {
  const uint16_t coeff700 = p->v[N - 1];

  for (unsigned i = 0; i < N; i++) {
    p->v[i] -= coeff700;
  }
}

// poly_clamp reduces each coefficient mod Q.
static void poly_clamp(struct poly *p) {
  for (unsigned i = 0; i < N; i++) {
    p->v[i] &= Q - 1;
  }
}


// Conversion functions
// --------------------

// poly2_from_poly sets |*out| to |in| mod 2.
static void poly2_from_poly(struct poly2 *out, const struct poly *in) {
  word_t *words = out->v;
  unsigned shift = 0;
  word_t word = 0;

  for (unsigned i = 0; i < N; i++) {
    word >>= 1;
    word |= (word_t)(in->v[i] & 1) << (BITS_PER_WORD - 1);
    shift++;

    if (shift == BITS_PER_WORD) {
      *words = word;
      words++;
      word = 0;
      shift = 0;
    }
  }

  word >>= BITS_PER_WORD - shift;
  *words = word;
}

// mod3 treats |a| is a signed number and returns |a| mod 3.
static uint16_t mod3(uint16_t a) {
  const int16_t signed_a = a;
  const int16_t q = ((int32_t)signed_a * 21845) >> 16;
  int16_t ret = signed_a - 3 * q;
  // At this point, |ret| is in {0, 1, 2, 3} and that needs to be mapped to {0,
  // 1, 2, 0}.
  return ret & ((ret & (ret >> 1)) - 1);
}

// poly3_from_poly sets |*out| to |in|.
static void poly3_from_poly(struct poly3 *out, const struct poly *in) {
  word_t *words_s = out->s.v;
  word_t *words_a = out->a.v;
  word_t s = 0;
  word_t a = 0;
  unsigned shift = 0;

  for (unsigned i = 0; i < N; i++) {
    // This duplicates the 13th bit upwards to the top of the uint16,
    // essentially treating it as a sign bit and converting into a signed int16.
    // The signed value is reduced mod 3, yeilding {0, 1, 2}.
    const uint16_t v = mod3((int16_t)(in->v[i] << 3) >> 3);
    s >>= 1;
    s |= (word_t)(v & 2) << (BITS_PER_WORD - 2);
    a >>= 1;
    a |= (word_t)(v & 1) << (BITS_PER_WORD - 1);
    shift++;

    if (shift == BITS_PER_WORD) {
      *words_s = s;
      words_s++;
      *words_a = a;
      words_a++;
      s = a = 0;
      shift = 0;
    }
  }

  s >>= BITS_PER_WORD - shift;
  a >>= BITS_PER_WORD - shift;
  *words_s = s;
  *words_a = a;
}

// poly3_from_poly_checked sets |*out| to |in|, which has coefficients in {0, 1,
// Q-1}. It returns a mask indicating whether all coefficients were found to be
// in that set.
static crypto_word_t poly3_from_poly_checked(struct poly3 *out,
                                             const struct poly *in) {
  word_t *words_s = out->s.v;
  word_t *words_a = out->a.v;
  word_t s = 0;
  word_t a = 0;
  unsigned shift = 0;
  crypto_word_t ok = CONSTTIME_TRUE_W;

  for (unsigned i = 0; i < N; i++) {
    const uint16_t v = in->v[i];
    // Maps {0, 1, Q-1} to {0, 1, 2}.
    uint16_t mod3 = v & 3;
    mod3 ^= mod3 >> 1;
    const uint16_t expected = (uint16_t)((~((mod3 >> 1) - 1)) | mod3) % Q;
    ok &= constant_time_eq_w(v, expected);

    s >>= 1;
    s |= (word_t)(mod3 & 2) << (BITS_PER_WORD - 2);
    a >>= 1;
    a |= (word_t)(mod3 & 1) << (BITS_PER_WORD - 1);
    shift++;

    if (shift == BITS_PER_WORD) {
      *words_s = s;
      words_s++;
      *words_a = a;
      words_a++;
      s = a = 0;
      shift = 0;
    }
  }

  s >>= BITS_PER_WORD - shift;
  a >>= BITS_PER_WORD - shift;
  *words_s = s;
  *words_a = a;

  return ok;
}

static void poly_from_poly2(struct poly *out, const struct poly2 *in) {
  const word_t *words = in->v;
  unsigned shift = 0;
  word_t word = *words;

  for (unsigned i = 0; i < N; i++) {
    out->v[i] = word & 1;
    word >>= 1;
    shift++;

    if (shift == BITS_PER_WORD) {
      words++;
      word = *words;
      shift = 0;
    }
  }
}

static void poly_from_poly3(struct poly *out, const struct poly3 *in) {
  const word_t *words_s = in->s.v;
  const word_t *words_a = in->a.v;
  word_t word_s = ~(*words_s);
  word_t word_a = *words_a;
  unsigned shift = 0;

  for (unsigned i = 0; i < N; i++) {
    out->v[i] = (uint16_t)(word_s & 1) - 1;
    out->v[i] |= word_a & 1;
    word_s >>= 1;
    word_a >>= 1;
    shift++;

    if (shift == BITS_PER_WORD) {
      words_s++;
      words_a++;
      word_s = ~(*words_s);
      word_a = *words_a;
      shift = 0;
    }
  }
}

// Polynomial inversion
// --------------------

// poly_invert_mod2 sets |*out| to |in^-1| (i.e. such that |*out|×|in| = 1), all
// mod 2. This isn't useful in itself, but is part of doing inversion mod Q.
static void poly_invert_mod2(struct poly *out, const struct poly *in) {
  // This algorithm follows algorithm 10 in the paper. (Although, in contrast to
  // the paper, k should start at zero, not one, and the rotation count is needs
  // to handle trailing zero coefficients.) The best explanation for why it
  // works is in the "Why it works" section of [NTRUTN14].

  struct poly2 b, c, f, g;
  poly2_from_poly(&f, in);
  OPENSSL_memset(&b, 0, sizeof(b));
  b.v[0] = 1;
  OPENSSL_memset(&c, 0, sizeof(c));

  // Set g to all ones.
  OPENSSL_memset(&g, 0xff, sizeof(struct poly2));
  g.v[WORDS_PER_POLY - 1] >>= BITS_PER_WORD - BITS_IN_LAST_WORD;

  crypto_word_t k = 0, deg_f = N - 1, deg_g = N - 1, rotation = 0;
  crypto_word_t still_going = CONSTTIME_TRUE_W;

  for (unsigned i = 0; i < 2 * (N - 1) - 1; i++) {
    const word_t s = 1 & still_going & f.v[0];
    const crypto_word_t should_swap =
        ~constant_time_is_zero_w(s) & constant_time_lt_w(deg_f, deg_g);
    poly2_cswap(&f, &g, should_swap);
    poly2_cswap(&b, &c, should_swap);
    const crypto_word_t deg_sum = should_swap & (deg_f ^ deg_g);
    deg_f ^= deg_sum;
    deg_g ^= deg_sum;
    poly2_fmadd(&f, &g, s);
    poly2_fmadd(&b, &c, s);

    poly2_rshift1(&f);
    poly2_lshift1(&c);

    deg_f--;
    k += 1 & still_going;
    const crypto_word_t f0_is_zero = constant_time_is_zero_w(f.v[0] & 1);
    rotation = constant_time_select_w(still_going & ~f0_is_zero, k, rotation);
    still_going = ~constant_time_is_zero_w(deg_f);
  }

  rotation -= N & constant_time_lt_w(N, rotation);
  poly2_rotr_consttime(&b, rotation);
  poly_from_poly2(out, &b);
}

// poly_invert sets |*out| to |in^-1| (i.e. such that |*out|×|in| = 1).
static void poly_invert(struct poly *out, const struct poly *in) {
  // Inversion mod Q, which is done based on the result of inverting mod
  // 2. See [NTRUTN14] paper, page three.
  struct poly a, *b, tmp;

  // a = -in.
  for (unsigned i = 0; i < N; i++) {
    a.v[i] = -in->v[i];
  }

  // b = in^-1 mod 2.
  b = out;
  poly_invert_mod2(b, in);

  // We are working mod Q=2**13 and we need to iterate ceil(log_2(13))
  // times, which is four.
  for (unsigned i = 0; i < 4; i++) {
    poly_mul(&tmp, &a, b);
    tmp.v[0] += 2;
    poly_mul(b, b, &tmp);
  }
}

// Marshal and unmarshal functions for various basic types.
// --------------------------------------------------------

#define POLY_BYTES 1138
#define POLY3_BYTES 140

static void poly_marshal(uint8_t out[POLY_BYTES], const struct poly *in) {
  const uint16_t *p = in->v;

  for (size_t i = 0; i < N / 8; i++) {
    out[0] = p[0];
    out[1] = (0x1f & (p[0] >> 8)) | ((p[1] & 0x07) << 5);
    out[2] = p[1] >> 3;
    out[3] = (3 & (p[1] >> 11)) | ((p[2] & 0x3f) << 2);
    out[4] = (0x7f & (p[2] >> 6)) | ((p[3] & 0x01) << 7);
    out[5] = p[3] >> 1;
    out[6] = (0xf & (p[3] >> 9)) | ((p[4] & 0x0f) << 4);
    out[7] = p[4] >> 4;
    out[8] = (1 & (p[4] >> 12)) | ((p[5] & 0x7f) << 1);
    out[9] = (0x3f & (p[5] >> 7)) | ((p[6] & 0x03) << 6);
    out[10] = p[6] >> 2;
    out[11] = (7 & (p[6] >> 10)) | ((p[7] & 0x1f) << 3);
    out[12] = p[7] >> 5;

    p += 8;
    out += 13;
  }

  // There are four remaining values.
  out[0] = p[0];
  out[1] = (0x1f & (p[0] >> 8)) | ((p[1] & 0x07) << 5);
  out[2] = p[1] >> 3;
  out[3] = (3 & (p[1] >> 11)) | ((p[2] & 0x3f) << 2);
  out[4] = (0x7f & (p[2] >> 6)) | ((p[3] & 0x01) << 7);
  out[5] = p[3] >> 1;
  out[6] = 0xf & (p[3] >> 9);
}

static int poly_unmarshal(struct poly *out, const uint8_t in[POLY_BYTES]) {
  uint16_t *p = out->v;

  for (size_t i = 0; i < N / 8; i++) {
    p[0] = (uint16_t)(in[0]) | (uint16_t)(in[1] & 0x1f) << 8;
    p[1] = (uint16_t)(in[1] >> 5) | (uint16_t)(in[2]) << 3 |
           (uint16_t)(in[3] & 3) << 11;
    p[2] = (uint16_t)(in[3] >> 2) | (uint16_t)(in[4] & 0x7f) << 6;
    p[3] = (uint16_t)(in[4] >> 7) | (uint16_t)(in[5]) << 1 |
           (uint16_t)(in[6] & 0xf) << 9;
    p[4] = (uint16_t)(in[6] >> 4) | (uint16_t)(in[7]) << 4 |
           (uint16_t)(in[8] & 1) << 12;
    p[5] = (uint16_t)(in[8] >> 1) | (uint16_t)(in[9] & 0x3f) << 7;
    p[6] = (uint16_t)(in[9] >> 6) | (uint16_t)(in[10]) << 2 |
           (uint16_t)(in[11] & 7) << 10;
    p[7] = (uint16_t)(in[11] >> 3) | (uint16_t)(in[12]) << 5;

    for (unsigned j = 0; j < 8; j++) {
      p[j] = (int16_t)(p[j] << 3) >> 3;
    }

    p += 8;
    in += 13;
  }

  // There are four coefficients remaining.
  p[0] = (uint16_t)(in[0]) | (uint16_t)(in[1] & 0x1f) << 8;
  p[1] = (uint16_t)(in[1] >> 5) | (uint16_t)(in[2]) << 3 |
         (uint16_t)(in[3] & 3) << 11;
  p[2] = (uint16_t)(in[3] >> 2) | (uint16_t)(in[4] & 0x7f) << 6;
  p[3] = (uint16_t)(in[4] >> 7) | (uint16_t)(in[5]) << 1 |
         (uint16_t)(in[6] & 0xf) << 9;

  // For now, allow no flexibility in the encoding.
  if ((in[6] & 0xf0) != 0) {
    return 0;
  }

  // Set the final coefficient as specifed in [HRSSNIST] 1.9.2 step 6.
  uint32_t sum = 0;
  for (size_t i = 0; i < N - 1; i++) {
    sum += out->v[i];
  }

  out->v[N - 1] = (uint16_t)(0u-sum);
  return 1;
}

// mod3_from_modQ maps {0, 1, Q-1, 65535} -> {0, 1, 2, 2}.
static uint16_t mod3_from_modQ(uint16_t v) {
  assert(v == 0 || v == 1 || v == Q - 1 || v == 0xffff);
  v &= 3;
  return v ^ (v >> 1);
}

// poly_marshal_mod3 marshals |in| to |out| where the coefficients of |in| are
// all in {0, 1, 2} and |in| is mod Φ(N).
static void poly_marshal_mod3(uint8_t out[POLY3_BYTES], const struct poly *in) {
  // Only 700 coefficients are marshaled because in[700] must be zero.
  const uint16_t *coeffs = in->v;
  for (size_t i = 0; i < POLY3_BYTES; i++) {
    const uint16_t coeffs0 = mod3_from_modQ(coeffs[0]);
    const uint16_t coeffs1 = mod3_from_modQ(coeffs[1]);
    const uint16_t coeffs2 = mod3_from_modQ(coeffs[2]);
    const uint16_t coeffs3 = mod3_from_modQ(coeffs[3]);
    const uint16_t coeffs4 = mod3_from_modQ(coeffs[4]);
    out[i] = coeffs0 + coeffs1 * 3 + coeffs2 * 9 + coeffs3 * 27 + coeffs4 * 81;
    coeffs += 5;
  }
}

// HRSS-specific functions
// -----------------------

// poly_short_sample implements the sampling algorithm given in [HRSSNIST]
// section 1.8.1. The output coefficients are in {0, 1, 0xffff} which makes some
// later computation easier.
static void poly_short_sample(struct poly *out,
                              const uint8_t in[HRSS_SAMPLE_BYTES]) {
  // We wish to calculate the difference (mod 3) between two, two-bit numbers.
  // Here is a table of results for a - b. Negative one is written as 0b11 so
  // that a couple of shifts can be used to sign-extend it. Any inpput value of
  // 0b11 is invalid and a convention is adopted that an invalid input results
  // in an invalid output (0b10).
  //
  //  b  a result
  // 00 00 00
  // 00 01 01
  // 00 10 11
  // 00 11 10
  // 01 00 11
  // 01 01 00
  // 01 10 01
  // 01 11 10
  // 10 00 01
  // 10 01 11
  // 10 10 00
  // 10 11 10
  // 11 00 10
  // 11 01 10
  // 11 10 10
  // 11 11 10
  //
  // The result column is encoded in a single-word lookup-table:
  // 0001 1110 1100 0110 0111 0010 1010 1010
  //   1    d    c    6    7    2    a    a
  static const uint32_t kLookup = 0x1dc672aa;

  // In order to generate pairs of numbers mod 3 (non-uniformly) we treat pairs
  // of bits in a uint32 as separate values and sum two random vectors of 1-bit
  // numbers. This works because these pairs are isolated because no carry can
  // spread between them.

  uint16_t *p = out->v;
  for (size_t i = 0; i < N / 8; i++) {
    uint32_t v;
    OPENSSL_memcpy(&v, in, sizeof(v));
    in += sizeof(v);

    uint32_t sums = (v & 0x55555555) + ((v >> 1) & 0x55555555);
    for (unsigned j = 0; j < 8; j++) {
      p[j] = (int32_t)(kLookup << ((sums & 15) << 1)) >> 30;
      sums >>= 4;
    }
    p += 8;
  }

  // There are four values remaining.
  uint16_t v;
  OPENSSL_memcpy(&v, in, sizeof(v));

  uint16_t sums = (v & 0x5555) + ((v >> 1) & 0x5555);
  for (unsigned j = 0; j < 4; j++) {
    p[j] = (int32_t)(kLookup << ((sums & 15) << 1)) >> 30;
    sums >>= 4;
  }

  out->v[N - 1] = 0;
}

// poly_short_sample_plus performs the T+ sample as defined in [HRSSNIST],
// section 1.8.2.
static void poly_short_sample_plus(struct poly *out,
                                   const uint8_t in[HRSS_SAMPLE_BYTES]) {
  poly_short_sample(out, in);

  // sum (and the product in the for loop) will overflow. But that's fine
  // because wrapping mod 2^16 is fine when working mod Q.
  int16_t sum = 0;
  for (unsigned i = 0; i < N - 1; i++) {
    sum += out->v[i] * out->v[i + 1];
  }

  // If the sum is negative, flip the sign of even-positioned coefficients. (See
  // page 8 of [HRSS].)
  sum >>= 15;
  const uint16_t scale = sum | (~sum & 1);
  for (unsigned i = 0; i < N; i += 2) {
    out->v[i] = out->v[i] * scale;
  }
}

// poly_lift computes the function discussed in [HRSS], appendix B.
static void poly_lift(struct poly *out, const struct poly *a) {
  // We wish to calculate a/(𝑥-1) mod Φ(N) over GF(3), where Φ(N) is the
  // Nth cyclotomic polynomial, i.e. 1 + 𝑥 + … + 𝑥^700 (since N is prime).

  // 1/(𝑥-1) has a fairly basic structure that we can exploit to speed this up:
  //
  // R.<x> = PolynomialRing(GF(3)…)
  // inv = R.cyclotomic_polynomial(1).inverse_mod(R.cyclotomic_polynomial(n))
  // list(inv)[:15]
  //   [1, 0, 2, 1, 0, 2, 1, 0, 2, 1, 0, 2, 1, 0, 2]
  //
  // This three-element pattern of coefficients repeats for the whole
  // polynomial.
  //
  // Next define the overbar operator such that z̅ = z[0] +
  // reverse(z[1:]). (Index zero of a polynomial here is the coefficient
  // of the constant term. So index one is the coefficient of 𝑥 and so
  // on.)
  //
  // A less odd way to define this is to see that z̅ negates the indexes,
  // so z̅[0] = z[-0], z̅[1] = z[-1] and so on.
  //
  // The use of z̅ is that, when working mod (𝑥^701 - 1), vz[0] = <v,
  // z̅>, vz[1] = <v, 𝑥z̅>, …. (Where <a, b> is the inner product: the sum
  // of the point-wise products.) Although we calculated the inverse mod
  // Φ(N), we can work mod (𝑥^N - 1) and reduce mod Φ(N) at the end.
  // (That's because (𝑥^N - 1) is a multiple of Φ(N).)
  //
  // When working mod (𝑥^N - 1), multiplication by 𝑥 is a right-rotation
  // of the list of coefficients.
  //
  // Thus we can consider what the pattern of z̅, 𝑥z̅, 𝑥^2z̅, … looks like:
  //
  // def reverse(xs):
  //   suffix = list(xs[1:])
  //   suffix.reverse()
  //   return [xs[0]] + suffix
  //
  // def rotate(xs):
  //   return [xs[-1]] + xs[:-1]
  //
  // zoverbar = reverse(list(inv) + [0])
  // xzoverbar = rotate(reverse(list(inv) + [0]))
  // x2zoverbar = rotate(rotate(reverse(list(inv) + [0])))
  //
  // zoverbar[:15]
  //   [1, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1]
  // xzoverbar[:15]
  //   [0, 1, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0]
  // x2zoverbar[:15]
  //   [2, 0, 1, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2]
  //
  // (For a formula for z̅, see lemma two of appendix B.)
  //
  // After the first three elements have been taken care of, all then have
  // a repeating three-element cycle. The next value (𝑥^3z̅) involves
  // three rotations of the first pattern, thus the three-element cycle
  // lines up. However, the discontinuity in the first three elements
  // obviously moves to a different position. Consider the difference
  // between 𝑥^3z̅ and z̅:
  //
  // [x-y for (x,y) in zip(zoverbar, x3zoverbar)][:15]
  //    [0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  //
  // This pattern of differences is the same for all elements, although it
  // obviously moves right with the rotations.
  //
  // From this, we reach algorithm eight of appendix B.

  // Handle the first three elements of the inner products.
  out->v[0] = a->v[0] + a->v[2];
  out->v[1] = a->v[1];
  out->v[2] = -a->v[0] + a->v[2];

  // Use the repeating pattern to complete the first three inner products.
  for (size_t i = 3; i < 699; i += 3) {
    out->v[0] += -a->v[i] + a->v[i + 2];
    out->v[1] += a->v[i] - a->v[i + 1];
    out->v[2] += a->v[i + 1] - a->v[i + 2];
  }

  // Handle the fact that the three-element pattern doesn't fill the
  // polynomial exactly (since 701 isn't a->v multiple of three).
  out->v[2] += a->v[700];
  out->v[0] -= a->v[699];
  out->v[1] += a->v[699] - a->v[700];

  // Calculate the remaining inner products by taking advantage of the
  // fact that the pattern repeats every three cycles and the pattern of
  // differences is moves with the rotation.
  for (size_t i = 3; i < N; i++) {
    out->v[i] = (out->v[i - 3] - (a->v[i - 2] + a->v[i - 1] + a->v[i]));
  }

  // Reduce mod Φ(N) by subtracting a multiple of out[700] from every
  // element and convert to mod Q. (See above about adding twice as
  // subtraction.)
  const word_t v = out->v[700];
  for (unsigned i = 0; i < N; i++) {
    const uint16_t vi_mod3 = mod3(out->v[i] - v);
    // Map {0, 1, 2} to {0, 1, 0xffff}.
    out->v[i] = (~((vi_mod3 >> 1) - 1)) | vi_mod3;
  }

  poly_mul_x_minus_1(out);
}

struct public_key {
  struct poly ph;
};

struct private_key {
  struct poly3 f, f_inverse;
  struct poly ph_inverse;
  uint8_t hmac_key[32];
};

void HRSS_generate_key(
    struct HRSS_public_key *out_pub, struct HRSS_private_key *out_priv,
    const uint8_t in[HRSS_SAMPLE_BYTES + HRSS_SAMPLE_BYTES + 32]) {
  OPENSSL_COMPILE_ASSERT(
      sizeof(struct HRSS_public_key) >= sizeof(struct public_key),
      hrss_public_key_too_small);
  OPENSSL_COMPILE_ASSERT(
      sizeof(struct HRSS_private_key) >= sizeof(struct private_key),
      hrss_private_key_too_small);
#if defined(__GNUC__) || defined(__clang__)
  OPENSSL_COMPILE_ASSERT(
      __alignof__(struct HRSS_public_key) == __alignof__(struct public_key),
      hrss_public_key_incorrect_alignment);
  OPENSSL_COMPILE_ASSERT(
      __alignof__(struct HRSS_private_key) == __alignof__(struct private_key),
      hrss_private_key_incorrect_alignment);
#endif

  struct public_key *pub = (struct public_key *)out_pub;
  struct private_key *priv = (struct private_key *)out_priv;

  OPENSSL_memcpy(priv->hmac_key, in + 2 * HRSS_SAMPLE_BYTES,
                 sizeof(priv->hmac_key));

  struct poly f;
  poly_short_sample_plus(&f, in);
  poly3_from_poly(&priv->f, &f);
  poly3_invert(&priv->f_inverse, &priv->f);

  // ph_phi1 is p (i.e. 3) × g × Φ(1) (i.e. 𝑥-1).
  struct poly pg_phi1;
  poly_short_sample_plus(&pg_phi1, in + HRSS_SAMPLE_BYTES);
  for (unsigned i = 0; i < N; i++) {
    pg_phi1.v[i] *= 3;
  }
  poly_mul_x_minus_1(&pg_phi1);

  struct poly pfg_phi1;
  poly_mul(&pfg_phi1, &f, &pg_phi1);

  struct poly pfg_phi1_inverse;
  poly_invert(&pfg_phi1_inverse, &pfg_phi1);

  poly_mul(&pub->ph, &pfg_phi1_inverse, &pg_phi1);
  poly_mul(&pub->ph, &pub->ph, &pg_phi1);
  poly_clamp(&pub->ph);

  poly_mul(&priv->ph_inverse, &pfg_phi1_inverse, &f);
  poly_mul(&priv->ph_inverse, &priv->ph_inverse, &f);
  poly_clamp(&priv->ph_inverse);
}

static void owf(uint8_t out[POLY_BYTES], const struct public_key *pub,
                const struct poly *m, const struct poly *r) {
  struct poly lifted_m;
  poly_lift(&lifted_m, m);

  struct poly prh_plus_m;
  poly_mul(&prh_plus_m, r, &pub->ph);
  for (unsigned i = 0; i < N; i++) {
    prh_plus_m.v[i] += lifted_m.v[i];
  }

  poly_marshal(out, &prh_plus_m);
}

static const char kConfirmationHash[] = "confirmation hash";
static const char kSharedKey[] = "shared key";

void HRSS_encap(uint8_t out_ciphertext[POLY_BYTES + 32],
                uint8_t out_shared_key[32],
                const struct HRSS_public_key *in_pub,
                const uint8_t in[HRSS_SAMPLE_BYTES + HRSS_SAMPLE_BYTES]) {
  struct public_key *pub = (struct public_key *)in_pub;
  struct poly m, r;
  poly_short_sample(&m, in);
  poly_short_sample(&r, in + HRSS_SAMPLE_BYTES);
  owf(out_ciphertext, pub, &m, &r);

  uint8_t m_bytes[POLY3_BYTES], r_bytes[POLY3_BYTES];
  poly_marshal_mod3(m_bytes, &m);
  poly_marshal_mod3(r_bytes, &r);

  SHA256_CTX hash_ctx;
  SHA256_Init(&hash_ctx);
  SHA256_Update(&hash_ctx, kConfirmationHash, sizeof(kConfirmationHash));
  SHA256_Update(&hash_ctx, m_bytes, sizeof(m_bytes));
  SHA256_Update(&hash_ctx, r_bytes, sizeof(r_bytes));
  SHA256_Final(out_ciphertext + POLY_BYTES, &hash_ctx);

  SHA256_Init(&hash_ctx);
  SHA256_Update(&hash_ctx, kSharedKey, sizeof(kSharedKey));
  SHA256_Update(&hash_ctx, m_bytes, sizeof(m_bytes));
  SHA256_Update(&hash_ctx, r_bytes, sizeof(r_bytes));
  SHA256_Update(&hash_ctx, out_ciphertext, POLY_BYTES + 32);
  SHA256_Final(out_shared_key, &hash_ctx);
}

void HRSS_decap(uint8_t out_shared_key[32],
                const struct HRSS_public_key *in_pub,
                const struct HRSS_private_key *in_priv,
                const uint8_t *ciphertext, size_t ciphertext_len) {
  struct public_key *pub = (struct public_key *)in_pub;
  struct private_key *priv = (struct private_key *)in_priv;

  unsigned out_len;
  if (NULL == HMAC(EVP_sha256(), priv->hmac_key, sizeof(priv->hmac_key),
                   ciphertext, ciphertext_len, out_shared_key, &out_len)) {
    abort();
  }
  assert(out_len == 32);

  // If the ciphertext is publicly invalid then a random shared key is still
  // returned to simply the logic of the caller, but this path is not constant
  // time.
  struct poly c;
  if (ciphertext_len != POLY_BYTES + 32 || !poly_unmarshal(&c, ciphertext)) {
    return;
  }

  struct poly f;
  poly_from_poly3(&f, &priv->f);

  struct poly cf;
  poly_mul(&cf, &c, &f);

  struct poly3 cf3;
  poly3_from_poly(&cf3, &cf);
  // Note that cf3 is not reduced mod Φ(N). That reduction is deferred.

  struct poly3 m3;
  poly3_mul(&m3, &cf3, &priv->f_inverse);
  poly3_mod_phiN(&m3);

  struct poly m, m_lifted;
  poly_from_poly3(&m, &m3);
  poly_lift(&m_lifted, &m);

  for (unsigned i = 0; i < N; i++) {
    c.v[i] -= m_lifted.v[i];
  }
  poly_mul(&c, &c, &priv->ph_inverse);
  poly_mod_phiN(&c);
  poly_clamp(&c);

  struct poly3 r3;
  crypto_word_t ok = poly3_from_poly_checked(&r3, &c);

  uint8_t expected_ciphertext[POLY_BYTES + 32];
  assert(ciphertext_len == sizeof(expected_ciphertext));
  owf(expected_ciphertext, pub, &m, &c);

  uint8_t m_bytes[POLY3_BYTES];
  uint8_t r_bytes[POLY3_BYTES];
  poly_marshal_mod3(m_bytes, &m);
  poly_marshal_mod3(r_bytes, &c);

  SHA256_CTX hash_ctx;
  SHA256_Init(&hash_ctx);
  SHA256_Update(&hash_ctx, kConfirmationHash, sizeof(kConfirmationHash));
  SHA256_Update(&hash_ctx, m_bytes, sizeof(m_bytes));
  SHA256_Update(&hash_ctx, r_bytes, sizeof(r_bytes));
  SHA256_Final(expected_ciphertext + POLY_BYTES, &hash_ctx);

  ok &= constant_time_is_zero_w(CRYPTO_memcmp(ciphertext, expected_ciphertext,
                                              sizeof(expected_ciphertext)));

  uint8_t shared_key[32];
  SHA256_Init(&hash_ctx);
  SHA256_Update(&hash_ctx, kSharedKey, sizeof(kSharedKey));
  SHA256_Update(&hash_ctx, m_bytes, sizeof(m_bytes));
  SHA256_Update(&hash_ctx, r_bytes, sizeof(r_bytes));
  SHA256_Update(&hash_ctx, expected_ciphertext, sizeof(expected_ciphertext));
  SHA256_Final(shared_key, &hash_ctx);

  for (unsigned i = 0; i < sizeof(shared_key); i++) {
    out_shared_key[i] =
        constant_time_select_8(ok, shared_key[i], out_shared_key[i]);
  }
}

void HRSS_serialize_public_key(uint8_t out[HRSS_PUBLIC_KEY_BYTES],
                               const struct HRSS_public_key *in_pub) {
  struct public_key *pub = (struct public_key *)in_pub;
  OPENSSL_memcpy(out, &pub->ph.v, N * sizeof(uint16_t));
}
