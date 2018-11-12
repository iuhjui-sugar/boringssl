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

#include <openssl/bn.h>
#include <openssl/cpu.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/sha.h>

#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
#include <emmintrin.h>
#endif

#if (defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)) && \
    (defined(__ARM_NEON__) || defined(__ARM_NEON))
#include <arm_neon.h>
#endif

#if defined(_MSC_VER)
#define RESTRICT
#else
#define RESTRICT restrict
#endif

#include "internal.h"
#include "../internal.h"

// This is an implementation of [HRSS], but with a KEM transformation based on
// [SXY]. The primary references are:

// HRSS: https://eprint.iacr.org/2017/667.pdf
// HRSSNIST:
// https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/round-1/submissions/NTRU_HRSS_KEM.zip
// SXY: https://eprint.iacr.org/2017/1005.pdf
// NTRUTN14:
// https://assets.onboardsecurity.com/static/downloads/NTRU/resources/NTRUTech014.pdf


// Vector operations.
//
// A couple of functions in this file can use vector operations to meaningful
// effect. If we're building for a target that has a supported vector unit,
// |HRSS_HAVE_VECTOR_UNIT| will be defined and |vec_t| will be typedefed to a
// 128-bit vector. The following functions abstract over the differences between
// NEON and SSE2 for implementing some vector operations.

// TODO: MSVC can likely also be made to work with vector operations.
#if (defined(OPENSSL_X86) || defined(OPENSSL_X86_64)) && \
    (defined(__clang__) || !defined(_MSC_VER))

#define HRSS_HAVE_VECTOR_UNIT
typedef __m128i vec_t;

// vec_capable returns one iff the current platform supports SSE2.
static int vec_capable(void) {
#if defined(__SSE2__)
  return 1;
#else
  int has_sse2 = (OPENSSL_ia32cap_P[0] & (1 << 26)) != 0;
  return has_sse2;
#endif
}

// vec_set duplicates the given value four times and returns the resulting
// vector.
static inline vec_t vec_set(uint32_t v) { return _mm_set1_epi32(v); }

// vec_add performs a pair-wise addition of four uint16s from |a| and |b|.
static inline vec_t vec_add(vec_t a, vec_t b) { return _mm_add_epi16(a, b); }

// vec_sub performs a pair-wise subtraction of four uint16s from |a| and |b|.
static inline vec_t vec_sub(vec_t a, vec_t b) { return _mm_sub_epi16(a, b); }

// vec_mul multiplies each uint16_t in |a| by |b| and returns the resulting
// vector.
static inline vec_t vec_mul(vec_t a, uint16_t b) {
  return _mm_mullo_epi16(a, _mm_set1_epi16(b));
}

// vec_fma multiplies each uint16_t in |b| by |c|, adds the result to |a|, and
// returns the resulting vector.
static inline vec_t vec_fma(vec_t a, vec_t b, uint16_t c) {
  return _mm_add_epi16(a, _mm_mullo_epi16(b, _mm_set1_epi16(c)));
}

// vec3_rshift_word right-shifts the 24 uint16_t's in |v| by one uint16.
static inline void vec3_rshift_word(vec_t v[3]) {
  // Intel's left and right shifting is backwards compared to the order in
  // memory because they're based on little-endian order of words (and not just
  // bytes). So the shifts in this function will be backwards from what one
  // might expect.
  const __m128i carry0 = _mm_srli_si128(v[0], 14);
  v[0] = _mm_slli_si128(v[0], 2);

  const __m128i carry1 = _mm_srli_si128(v[1], 14);
  v[1] = _mm_slli_si128(v[1], 2);
  v[1] |= carry0;

  v[2] = _mm_slli_si128(v[2], 2);
  v[2] |= carry1;
}

// vec4_rshift_word right-shifts the 32 uint16_t's in |v| by one uint16.
static inline void vec4_rshift_word(vec_t v[4]) {
  // Intel's left and right shifting is backwards compared to the order in
  // memory because they're based on little-endian order of words (and not just
  // bytes). So the shifts in this function will be backwards from what one
  // might expect.
  const __m128i carry0 = _mm_srli_si128(v[0], 14);
  v[0] = _mm_slli_si128(v[0], 2);

  const __m128i carry1 = _mm_srli_si128(v[1], 14);
  v[1] = _mm_slli_si128(v[1], 2);
  v[1] |= carry0;

  const __m128i carry2 = _mm_srli_si128(v[2], 14);
  v[2] = _mm_slli_si128(v[2], 2);
  v[2] |= carry1;

  v[3] = _mm_slli_si128(v[3], 2);
  v[3] |= carry2;
}

// vec_merge_3_5 takes the final three uint16_t's from |left|, appends the first
// five from |right|, and returns the resulting vector.
static inline vec_t vec_merge_3_5(vec_t left, vec_t right) {
  return _mm_srli_si128(left, 10) | _mm_slli_si128(right, 6);
}

// poly3_vec_lshift1 left-shifts the 768 bits in |a_s|, and in |a_a|, by one
// bit.
static inline void poly3_vec_lshift1(vec_t a_s[6], vec_t a_a[6]) {
  vec_t carry_s = {0};
  vec_t carry_a = {0};

  for (int i = 0; i < 6; i++) {
    vec_t next_carry_s = _mm_srli_epi64(a_s[i], 63);
    a_s[i] = _mm_slli_epi64(a_s[i], 1);
    a_s[i] |= _mm_slli_si128(next_carry_s, 8);
    a_s[i] |= carry_s;
    carry_s = _mm_srli_si128(next_carry_s, 8);

    vec_t next_carry_a = _mm_srli_epi64(a_a[i], 63);
    a_a[i] = _mm_slli_epi64(a_a[i], 1);
    a_a[i] |= _mm_slli_si128(next_carry_a, 8);
    a_a[i] |= carry_a;
    carry_a = _mm_srli_si128(next_carry_a, 8);
  }
}

// poly3_vec_rshift1 right-shifts the 768 bits in |a_s|, and in |a_a|, by one
// bit.
static inline void poly3_vec_rshift1(vec_t a_s[6], vec_t a_a[6]) {
  vec_t carry_s = {0};
  vec_t carry_a = {0};

  for (int i = 5; i >= 0; i--) {
    const vec_t next_carry_s = _mm_slli_epi64(a_s[i], 63);
    a_s[i] = _mm_srli_epi64(a_s[i], 1);
    a_s[i] |= _mm_srli_si128(next_carry_s, 8);
    a_s[i] |= carry_s;
    carry_s = _mm_slli_si128(next_carry_s, 8);

    const vec_t next_carry_a = _mm_slli_epi64(a_a[i], 63);
    a_a[i] = _mm_srli_epi64(a_a[i], 1);
    a_a[i] |= _mm_srli_si128(next_carry_a, 8);
    a_a[i] |= carry_a;
    carry_a = _mm_slli_si128(next_carry_a, 8);
  }
}

// vec_broadcast_bit duplicates the least-significant bit in |a| to all bits in
// a vector and returns the result.
static inline vec_t vec_broadcast_bit(vec_t a) {
  return _mm_shuffle_epi32(_mm_srai_epi32(_mm_slli_epi64(a, 63), 31),
                           0b01010101);
}

#elif (defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)) && \
    (defined(__ARM_NEON__) || defined(__ARM_NEON))

#define HRSS_HAVE_VECTOR_UNIT
typedef uint16x8_t vec_t;

// These functions perform the same actions as the SSE2 function of the same
// name, above.

static int vec_capable() { return CRYPTO_is_NEON_capable(); }

static inline vec_t vec_add(vec_t a, vec_t b) { return a + b; }

static inline vec_t vec_sub(vec_t a, vec_t b) { return a - b; }

static inline vec_t vec_mul(vec_t a, uint16_t b) { return vmulq_n_u16(a, b); }

static inline vec_t vec_fma(vec_t a, vec_t b, uint16_t c) {
  return vmlaq_n_u16(a, b, c);
}

static inline void vec3_rshift_word(vec_t v[3]) {
  const uint16x8_t kZero = {0};
  v[2] = vextq_u16(v[1], v[2], 7);
  v[1] = vextq_u16(v[0], v[1], 7);
  v[0] = vextq_u16(kZero, v[0], 7);
}

static inline void vec4_rshift_word(vec_t v[4]) {
  const uint16x8_t kZero = {0};
  v[3] = vextq_u16(v[2], v[3], 7);
  v[2] = vextq_u16(v[1], v[2], 7);
  v[1] = vextq_u16(v[0], v[1], 7);
  v[0] = vextq_u16(kZero, v[0], 7);
}

static inline vec_t vec_merge_3_5(vec_t left, vec_t right) {
  return vextq_u16(left, right, 5);
}

#if !defined(OPENSSL_AARCH64)

static inline vec_t vec_set(uint16_t v) { return vdupq_n_u16(v); }

static inline vec_t vec_broadcast_bit(vec_t a) {
  a = (vec_t) vshrq_n_s16(((int16x8_t) a) << 15, 15);
  return vdupq_lane_u16(vget_low_u16(a), 0);
}

static inline void poly3_vec_lshift1(vec_t a_s[6], vec_t a_a[6]) {
  vec_t carry_s = {0};
  vec_t carry_a = {0};
  const vec_t kZero = {0};

  for (int i = 0; i < 6; i++) {
    vec_t next_carry_s = a_s[i] >> 15;
    a_s[i] <<= 1;
    a_s[i] |= vextq_u16(kZero, next_carry_s, 7);
    a_s[i] |= carry_s;
    carry_s = vextq_u16(next_carry_s, kZero, 7);

    vec_t next_carry_a = a_a[i] >> 15;
    a_a[i] <<= 1;
    a_a[i] |= vextq_u16(kZero, next_carry_a, 7);
    a_a[i] |= carry_a;
    carry_a = vextq_u16(next_carry_a, kZero, 7);
  }
}

static inline void poly3_vec_rshift1(vec_t a_s[6], vec_t a_a[6]) {
  vec_t carry_s = {0};
  vec_t carry_a = {0};
  const vec_t kZero = {0};

  for (int i = 5; i >= 0; i--) {
    vec_t next_carry_s = a_s[i] << 15;
    a_s[i] >>= 1;
    a_s[i] |= vextq_u16(next_carry_s, kZero, 1);
    a_s[i] |= carry_s;
    carry_s = vextq_u16(kZero, next_carry_s, 1);

    vec_t next_carry_a = a_a[i] << 15;
    a_a[i] >>= 1;
    a_a[i] |= vextq_u16(next_carry_a, kZero, 1);
    a_a[i] |= carry_a;
    carry_a = vextq_u16(kZero, next_carry_a, 1);
  }
}

#endif  // !OPENSSL_AARCH64

#endif  // (ARM || AARCH64) && NEON

// Polynomials in this scheme have N terms.
// #define N 701

// Underlying data types and arithmetic operations.
// ------------------------------------------------

// Binary polynomials.

// poly2 represents a degree-N polynomial over GF(2). The words are in little-
// endian order, i.e. the coefficient of x^0 is the LSB of the first word. The
// final word is only partially used since N is not a multiple of the word size.

// Defined in internal.h:
// struct poly2 {
//  word_t v[WORDS_PER_POLY];
// };

OPENSSL_UNUSED static void hexdump(const void *void_in, size_t len) {
  const uint8_t *in = (const uint8_t *)void_in;
  for (size_t i = 0; i < len; i++) {
    printf("%02x", in[i]);
  }
  printf("\n");
}

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
// |out|. The shift count, |bits|, must be a non-zero multiple of the word size.
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
// The shift count, |bits|, must be a non-zero power of two that is less than
// |BITS_PER_WORD|.
static void poly2_rotr_bits(struct poly2 *out, const struct poly2 *in,
                            size_t bits) {
  assert(bits <= BITS_PER_WORD / 2);
  assert(bits != 0);
  assert((bits & (bits - 1)) == 0);
  assert(out != in);

  // BITS_PER_WORD/2 is the greatest legal value of |bits|. If
  // |BITS_IN_LAST_WORD| is smaller than this then the code below doesn't work
  // because more than the last word needs to carry down in the previous one and
  // so on.
  OPENSSL_STATIC_ASSERT(
      BITS_IN_LAST_WORD >= BITS_PER_WORD / 2,
      "there are more carry bits than fit in BITS_IN_LAST_WORD");

  word_t carry = in->v[WORDS_PER_POLY - 1] << (BITS_PER_WORD - bits);

  for (size_t i = WORDS_PER_POLY - 2; i < WORDS_PER_POLY; i--) {
    out->v[i] = carry | in->v[i] >> bits;
    carry = in->v[i] << (BITS_PER_WORD - bits);
  }

  word_t last_word = carry >> (BITS_PER_WORD - BITS_IN_LAST_WORD) |
                     in->v[WORDS_PER_POLY - 1] >> bits;
  last_word &= (UINT64_C(1) << BITS_IN_LAST_WORD) - 1;
  out->v[WORDS_PER_POLY - 1] = last_word;
}

// HRSS_poly2_rotr_consttime right-rotates |p| by |bits| in constant-time.
void HRSS_poly2_rotr_consttime(struct poly2 *p, size_t bits) {
  assert(bits <= N);

  // Constant-time rotation is implemented by calculating the rotations of
  // powers-of-two bits and throwing away the unneeded values. 2^9 (i.e. 512) is
  // the largest power-of-two shift that we need to consider because 2^10 > N.
#define HRSS_POLY2_MAX_SHIFT 9
  size_t shift = HRSS_POLY2_MAX_SHIFT;
  OPENSSL_STATIC_ASSERT((1 << (HRSS_POLY2_MAX_SHIFT + 1)) > N,
                        "maximum shift is too small");
  OPENSSL_STATIC_ASSERT((1 << HRSS_POLY2_MAX_SHIFT) <= N,
                        "maximum shift is too large");
  struct poly2 shifted;

  for (; (UINT64_C(1) << shift) >= BITS_PER_WORD; shift--) {
    poly2_rotr_words(&shifted, p, UINT64_C(1) << shift);
    poly2_cmov(p, &shifted, ~((1 & (bits >> shift)) - 1));
  }

  for (; shift < HRSS_POLY2_MAX_SHIFT; shift--) {
    poly2_rotr_bits(&shifted, p, UINT64_C(1) << shift);
    poly2_cmov(p, &shifted, ~((1 & (bits >> shift)) - 1));
  }
#undef HRSS_POLY2_MAX_SHIFT
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
// ('s' is for sign, and 'a' for absolute value.)
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
//
// Negating a value just involves swapping s and a.
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
    printf(BN_HEX_FMT2, p.s.v[i]);
  }
  printf("] [");
  for (unsigned i = 0; i < WORDS_PER_POLY; i++) {
    if (i) {
      printf(" ");
    }
    printf(BN_HEX_FMT2, p.a.v[i]);
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
static word_t lsb_to_all(word_t v) { return ~((v & 1) - 1); }

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
  HRSS_poly2_rotr_consttime(&p->s, bits);
  HRSS_poly2_rotr_consttime(&p->a, bits);
}

// poly3_fmadd sets |out| to |out| + |in|×m, where m is (ms, ma).
static void poly3_fmadd(struct poly3 *RESTRICT out,
                        const struct poly3 *RESTRICT in, word_t ms, word_t ma) {
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

  p->s.v[WORDS_PER_POLY - 1] &= (UINT64_C(1) << BITS_IN_LAST_WORD) - 1;
  p->a.v[WORDS_PER_POLY - 1] &= (UINT64_C(1) << BITS_IN_LAST_WORD) - 1;
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

// poly3_span represents a pointer into a poly3.
struct poly3_span {
  word_t *s;
  word_t *a;
};

// poly3_word_add sets (|out_s|, |out_a|) to (|s1|, |a1|) + (|s2|, |a2|).
static void poly3_word_add(word_t *out_s, word_t *out_a, const word_t s1,
                           const word_t a1, const word_t s2, const word_t a2) {
  const word_t t1 = ~(s1 | a1);
  const word_t t2 = ~(s2 | a2);
  *out_s = (a1 & a2) ^ (t1 & s2) ^ (t2 & s1);
  *out_a = (s1 & s2) ^ (t1 & a2) ^ (t2 & a1);
}

// poly3_span_add adds |n| words of values from |a| and |b| and writes the
// result to |out|.
static void poly3_span_add(const struct poly3_span *out,
                           const struct poly3_span *a,
                           const struct poly3_span *b, size_t n) {
  for (size_t i = 0; i < n; i++) {
    poly3_word_add(&out->s[i], &out->a[i], a->s[i], a->a[i], b->s[i], b->a[i]);
  }
}

// poly3_span_sub subtracts |n| words of |b| from |n| words of |a|.
static void poly3_span_sub(const struct poly3_span *a,
                           const struct poly3_span *b, size_t n) {
  for (size_t i = 0; i < n; i++) {
    // Swapping |b->s| and |b->a| negates the value being added.
    poly3_word_add(&a->s[i], &a->a[i], a->s[i], a->a[i], b->a[i], b->s[i]);
  }
}

// poly3_mul_aux is a recursive function that multiplies |n| words from |a| and
// |b| and writes 2×|n| words to |out|, using |scratch| as needed.
static void poly3_mul_aux(const struct poly3_span *out,
                          const struct poly3_span *scratch,
                          const struct poly3_span *a,
                          const struct poly3_span *b, size_t n) {
  if (n == 1) {
    word_t r_s_low = 0, r_s_high = 0, r_a_low = 0, r_a_high = 0;
    word_t b_s = b->s[0], b_a = b->a[0];
    const word_t a_s = a->s[0], a_a = a->a[0];

    for (size_t i = 0; i < BITS_PER_WORD; i++) {
      // Multiply (s, a) by the next value from (b_s, b_a).
      const word_t v_s = lsb_to_all(b_s);
      const word_t v_a = lsb_to_all(b_a);
      b_s >>= 1;
      b_a >>= 1;

      const word_t m_s = (v_s & a_a) ^ (a_s & v_a);
      const word_t m_a = (a_s & v_s) ^ (a_a & v_a);

      if (i == 0) {
        // Special case otherwise the code tries to shift by BITS_PER_WORD
        // below, which doesn't do anything.
        r_s_low = m_s;
        r_a_low = m_a;
        continue;
      }

      // Shift the multiplication result to the correct position.
      const word_t m_s_low = m_s << i;
      const word_t m_s_high = m_s >> (BITS_PER_WORD - i);
      const word_t m_a_low = m_a << i;
      const word_t m_a_high = m_a >> (BITS_PER_WORD - i);

      // Add into the result.
      poly3_word_add(&r_s_low, &r_a_low, r_s_low, r_a_low, m_s_low, m_a_low);
      poly3_word_add(&r_s_high, &r_a_high, r_s_high, r_a_high, m_s_high,
                     m_a_high);
    }

    out->s[0] = r_s_low;
    out->s[1] = r_s_high;
    out->a[0] = r_a_low;
    out->a[1] = r_a_high;
    return;
  }

  // Karatsuba multiplication.
  // https://en.wikipedia.org/wiki/Karatsuba_algorithm

  // When |n| is odd, the two "halves" will have different lengths. The first
  // is always the smaller.
  const size_t low_len = n / 2;
  const size_t high_len = n - low_len;
  const struct poly3_span a_high = {&a->s[low_len], &a->a[low_len]};
  const struct poly3_span b_high = {&b->s[low_len], &b->a[low_len]};

  // Store a_1 + a_0 in the first half of |out| and b_1 + b_0 in the second
  // half.
  const struct poly3_span a_cross_sum = *out;
  const struct poly3_span b_cross_sum = {&out->s[high_len], &out->a[high_len]};
  poly3_span_add(&a_cross_sum, a, &a_high, low_len);
  poly3_span_add(&b_cross_sum, b, &b_high, low_len);
  if (high_len != low_len) {
    a_cross_sum.s[low_len] = a_high.s[low_len];
    a_cross_sum.a[low_len] = a_high.a[low_len];
    b_cross_sum.s[low_len] = b_high.s[low_len];
    b_cross_sum.a[low_len] = b_high.a[low_len];
  }

  const struct poly3_span child_scratch = {&scratch->s[2 * high_len],
                                           &scratch->a[2 * high_len]};
  const struct poly3_span out_mid = {&out->s[low_len], &out->a[low_len]};
  const struct poly3_span out_high = {&out->s[2 * low_len],
                                      &out->a[2 * low_len]};

  // Calculate (a_1 + a_0) × (b_1 + b_0) and write to scratch buffer.
  poly3_mul_aux(scratch, &child_scratch, &a_cross_sum, &b_cross_sum, high_len);
  // Calculate a_1 × b_1.
  poly3_mul_aux(&out_high, &child_scratch, &a_high, &b_high, high_len);
  // Calculate a_0 × b_0.
  poly3_mul_aux(out, &child_scratch, a, b, low_len);

  // Subtract those last two products from the first.
  poly3_span_sub(scratch, out, low_len * 2);
  poly3_span_sub(scratch, &out_high, high_len * 2);

  // Add the middle product into the output.
  poly3_span_add(&out_mid, &out_mid, scratch, high_len * 2);
}

// poly3_mul sets |*out| to |x|×|y| mod Φ(N).
static void poly3_mul(struct poly3 *out, const struct poly3 *x,
                      const struct poly3 *y) {
  word_t prod_s[WORDS_PER_POLY * 2];
  word_t prod_a[WORDS_PER_POLY * 2];
  word_t scratch_s[WORDS_PER_POLY * 2 + 2];
  word_t scratch_a[WORDS_PER_POLY * 2 + 2];
  const struct poly3_span prod_span = {prod_s, prod_a};
  const struct poly3_span scratch_span = {scratch_s, scratch_a};
  const struct poly3_span x_span = {(word_t *)x->s.v, (word_t *)x->a.v};
  const struct poly3_span y_span = {(word_t *)y->s.v, (word_t *)y->a.v};

  poly3_mul_aux(&prod_span, &scratch_span, &x_span, &y_span, WORDS_PER_POLY);

  // |prod| needs to be reduced mod (𝑥^n - 1), which just involves adding the
  // upper-half to the lower-half. However, N is 701, which isn't a multiple of
  // BITS_PER_WORD, so the upper-half vectors all have to be shifted before
  // being added to the lower-half.
  for (size_t i = 0; i < WORDS_PER_POLY; i++) {
    word_t v_s = prod_s[WORDS_PER_POLY + i - 1] >> BITS_IN_LAST_WORD;
    v_s |= prod_s[WORDS_PER_POLY + i] << (BITS_PER_WORD - BITS_IN_LAST_WORD);
    word_t v_a = prod_a[WORDS_PER_POLY + i - 1] >> BITS_IN_LAST_WORD;
    v_a |= prod_a[WORDS_PER_POLY + i] << (BITS_PER_WORD - BITS_IN_LAST_WORD);

    poly3_word_add(&out->s.v[i], &out->a.v[i], prod_s[i], prod_a[i], v_s, v_a);
  }

  poly3_mod_phiN(out);
}

#if defined(HRSS_HAVE_VECTOR_UNIT) && !defined(OPENSSL_AARCH64)

// poly3_vec_cswap swaps (|a_s|, |a_a|) and (|b_s|, |b_a|) if |swap| is
// |0xff..ff|. Otherwise, |swap| must be zero.
static inline void poly3_vec_cswap(vec_t a_s[6], vec_t a_a[6], vec_t b_s[6],
                                   vec_t b_a[6], const vec_t swap) {
  for (int i = 0; i < 6; i++) {
    const vec_t sum_s = swap & (a_s[i] ^ b_s[i]);
    a_s[i] ^= sum_s;
    b_s[i] ^= sum_s;

    const vec_t sum_a = swap & (a_a[i] ^ b_a[i]);
    a_a[i] ^= sum_a;
    b_a[i] ^= sum_a;
  }
}

// poly3_vec_fmadd adds (|ms|, |ma|) × (|b_s|, |b_a|) to (|a_s|, |a_a|).
static inline void poly3_vec_fmadd(vec_t a_s[6], vec_t a_a[6], vec_t b_s[6],
                                   vec_t b_a[6], const vec_t ms,
                                   const vec_t ma) {
  for (int i = 0; i < 6; i++) {
    const vec_t s = b_s[i];
    const vec_t a = b_a[i];
    const vec_t product_s = (s & ma) ^ (ms & a);
    const vec_t product_a = (ms & s) ^ (ma & a);
    const vec_t orig_s = a_s[i];
    const vec_t orig_a = a_a[i];
    const vec_t t1 = ~(orig_s | orig_a);
    const vec_t t2 = ~(product_s | product_a);
    a_s[i] = (orig_a & product_a) ^ (t1 & product_s) ^ (t2 & orig_s);
    a_a[i] = (orig_s & product_s) ^ (t1 & product_a) ^ (t2 & orig_a);
  }
}

// word_from_vec returns an arbitrary 32-bit subspan of |v|.
static inline word_t word_from_vec(vec_t v) {
  word_t ret;
  memcpy(&ret, &v, sizeof(ret));
  return ret;
}

// poly3_invert sets |*out| to |in|^-1, i.e. such that |out|×|in| == 1.
static void poly3_invert_vec(struct poly3 *out, const struct poly3 *in) {
  // This algorithm follows algorithm 10 in the paper. (Although, in contrast
  // to the paper, k should start at zero, not one, and the rotation count is
  // needs to handle trailing zero coefficients.) The best explanation for why
  // it works is in the "Why it works" section of [NTRUTN14].

  vec_t b_s[6], b_a[6], c_s[6], c_a[6], f_s[6], f_a[6], g_s[6], g_a[6];
  const vec_t kZero = {0};
  static const uint8_t kOneBytes[sizeof(vec_t)] = {1};
  static const uint8_t kBottomSixtyOne[sizeof(vec_t)] = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f};

  memset(b_s, 0, sizeof(b_s));
  memcpy(b_a, kOneBytes, sizeof(kOneBytes));
  memset(&b_a[1], 0, 5 * sizeof(vec_t));

  memset(c_s, 0, sizeof(c_s));
  memset(c_a, 0, sizeof(c_a));

  f_s[5] = kZero;
  memcpy(f_s, in->s.v, WORDS_PER_POLY * sizeof(word_t));
  f_a[5] = kZero;
  memcpy(f_a, in->a.v, WORDS_PER_POLY * sizeof(word_t));

  // Set g to all ones.
  memset(g_s, 0, sizeof(g_s));
  memset(g_a, 0xff, 5 * sizeof(vec_t));
  memcpy(&g_a[5], kBottomSixtyOne, sizeof(kBottomSixtyOne));

  crypto_word_t k = 0, deg_f = N - 1, deg_g = N - 1, rotation = 0;
  vec_t f0s = {0}, f0a = {0};
  vec_t still_going;
  memset(&still_going, 0xff, sizeof(still_going));

  for (unsigned i = 0; i < 2 * (N - 1) - 1; i++) {
    const vec_t s_a = vec_broadcast_bit(
        still_going & ((f_a[0] & g_s[0]) ^ (f_s[0] & g_a[0])));
    const vec_t s_s = vec_broadcast_bit(
        still_going & ((f_a[0] & g_a[0]) ^ (f_s[0] & g_s[0])));
    const vec_t should_swap =
        (s_s | s_a) & vec_set(constant_time_lt_w(deg_f, deg_g));

    poly3_vec_cswap(f_s, f_a, g_s, g_a, should_swap);
    poly3_vec_fmadd(f_s, f_a, g_s, g_a, s_s, s_a);
    poly3_vec_rshift1(f_s, f_a);

    poly3_vec_cswap(b_s, b_a, c_s, c_a, should_swap);
    poly3_vec_fmadd(b_s, b_a, c_s, c_a, s_s, s_a);
    poly3_vec_lshift1(c_s, c_a);

    const word_t should_swap_word = word_from_vec(should_swap);
    const word_t still_going_word = word_from_vec(still_going);

    const crypto_word_t deg_sum = should_swap_word & (deg_f ^ deg_g);
    deg_f ^= deg_sum;
    deg_g ^= deg_sum;

    deg_f--;
    k += 1 & still_going_word;
    const vec_t f0_is_zero = ~vec_broadcast_bit(f_s[0] | f_a[0]);
    const crypto_word_t f0_is_zero_word = word_from_vec(f0_is_zero);

    rotation = constant_time_select_w(still_going_word & ~f0_is_zero_word, k,
                                      rotation);
    const vec_t f0s_sum = (still_going & ~f0_is_zero) & (f_s[0] ^ f0s);
    f0s ^= f0s_sum;
    const vec_t f0a_sum = (still_going & ~f0_is_zero) & (f_a[0] ^ f0a);
    f0a ^= f0a_sum;

    still_going = ~vec_set(constant_time_is_zero_w(deg_f));
  }

  rotation -= N & constant_time_lt_w(N, rotation);
  memcpy(out->s.v, b_s, WORDS_PER_POLY * sizeof(word_t));
  memcpy(out->a.v, b_a, WORDS_PER_POLY * sizeof(word_t));
  poly3_rotr_consttime(out, rotation);
  poly3_mul_const(out, word_from_vec(f0s), word_from_vec(f0a));
  poly3_mod_phiN(out);
}

#endif  // HRSS_HAVE_VECTOR_UNIT

// poly3_invert sets |*out| to |in|^-1, i.e. such that |out|×|in| == 1.
static void poly3_invert(struct poly3 *out, const struct poly3 *in) {
  // The vector version of this function seems slightly slower on AArch64, but
  // is useful on ARMv7 and x86-64.
#if defined(HRSS_HAVE_VECTOR_UNIT) && !defined(OPENSSL_AARCH64)
  if (vec_capable()) {
    poly3_invert_vec(out, in);
    return;
  }
#endif

  // This algorithm follows algorithm 10 in the paper. (Although, in contrast
  // to the paper, k should start at zero, not one, and the rotation count is
  // needs to handle trailing zero coefficients.) The best explanation for why
  // it works is in the "Why it works" section of [NTRUTN14].

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
#if defined(HRSS_HAVE_VECTOR_UNIT)
  alignas(16)
#endif
      uint16_t v[N + 3];
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

#if defined(HRSS_HAVE_VECTOR_UNIT)

// kVecsPerPoly is the number of 128-bit vectors needed to represent a
// polynomial.
#define VECS_PER_POLY ((N + 7) / (sizeof(vec_t) / 2))

// poly_mul_vec_aux is a recursive function that multiplies |n| words from |a|
// and |b| and writes 2×|n| words to |out|, using |scratch| as needed.
static void poly_mul_vec_aux(vec_t *restrict out, vec_t *restrict scratch,
                             const vec_t *a, const vec_t *b, const size_t n) {
  // In [HRSS], the technique they used for polynomial multiplication is
  // described: they start with Toom-4 at the top level and then two layers of
  // Katatsuba. Katatsuba is a specific instance of the general Toom–Cook
  // decomposition, which splits an input n-ways and produces 2n-1
  // multiplications of those parts. So, starting with 704 coefficients (rounded
  // up from 701 to have more factors of two), Toom-4 gives seven
  // multiplications of degree-174 polynomials. Each round of Katatsuba (which
  // is Toom-2) increases the number of multiplications by a factor of three
  // while halving the size of the values being multiplied. So two rounds gives
  // 63 multiplications of degree-44 polynomials. Then they (I think) form
  // vectors by gathering all 63 coefficients of each power together, for each
  // input, and doing more rounds of Katatsuba on the vectors until they bottom-
  // out somewhere with schoolbook multiplication.
  //
  // I tried something like that for NEON. NEON vectors are 128 bits so hold
  // eight coefficients. I wrote a function that did Karatsuba on eight
  // multiplications at the same time, using such vectors, and a Go script that
  // decomposed from degree-704, with Katatsuba in non-transposed form, until it
  // reached multiplications of degree-44. It batched up those 81
  // multiplications into lots of eight with a single one left over (which was
  // handled directly).
  //
  // It worked, but it was significantly slower than the dumb algorithm used
  // below. Potentially that was because I misunderstood how [HRSS] did it, or
  // because Clang is bad at generating good code from NEON intrinsics on ARMv7.
  // (Which is true: the code generated by Clang for the below is pretty crap.)
  //
  // This algorithm is much simplier. It just does Katatsuba decomposition all
  // the way down and never transposes. When it gets down to degree-16 or
  // degree-24 values, they are multiplied using schoolbook multiplication and
  // vector intrinsics. The vector operations form each of the eight phase-
  // shifts of one of the inputs and multiply and add them add into the result
  // at the correct places. This means that 33% (degree-16) or 25% (degree-24)
  // of the multiplies and adds are wasted, but it does ok.
  if (n == 2) {
    vec_t result[4];
    vec_t vec_a[3];
    static const vec_t kZero = {0};
    vec_a[0] = a[0];
    vec_a[1] = a[1];
    vec_a[2] = kZero;

    const uint16_t *b_words = (const uint16_t *)b;
    result[0] = vec_mul(vec_a[0], b_words[0]);
    result[1] = vec_mul(vec_a[1], b_words[0]);

    result[1] = vec_fma(result[1], vec_a[0], b_words[8]);
    result[2] = vec_mul(vec_a[1], b_words[8]);
    result[3] = kZero;

    vec3_rshift_word(vec_a);

#define BLOCK(x, y)                                             \
  result[x + 0] = vec_fma(result[x + 0], vec_a[0], b_words[y]); \
  result[x + 1] = vec_fma(result[x + 1], vec_a[1], b_words[y]); \
  result[x + 2] = vec_fma(result[x + 2], vec_a[2], b_words[y]);

    BLOCK(0, 1);
    BLOCK(1, 9);

    vec3_rshift_word(vec_a);

    BLOCK(0, 2);
    BLOCK(1, 10);

    vec3_rshift_word(vec_a);

    BLOCK(0, 3);
    BLOCK(1, 11);

    vec3_rshift_word(vec_a);

    BLOCK(0, 4);
    BLOCK(1, 12);

    vec3_rshift_word(vec_a);

    BLOCK(0, 5);
    BLOCK(1, 13);

    vec3_rshift_word(vec_a);

    BLOCK(0, 6);
    BLOCK(1, 14);

    vec3_rshift_word(vec_a);

    BLOCK(0, 7);
    BLOCK(1, 15);

#undef BLOCK

    memcpy(out, result, sizeof(result));
    return;
  }

  if (n == 3) {
    vec_t result[6];
    vec_t vec_a[4];
    static const vec_t kZero = {0};
    vec_a[0] = a[0];
    vec_a[1] = a[1];
    vec_a[2] = a[2];
    vec_a[3] = kZero;

    const uint16_t *b_words = (const uint16_t *)b;
    result[0] = vec_mul(a[0], b_words[0]);
    result[1] = vec_mul(a[1], b_words[0]);
    result[2] = vec_mul(a[2], b_words[0]);

#define BLOCK_PRE(x, y)                                         \
  result[x + 0] = vec_fma(result[x + 0], vec_a[0], b_words[y]); \
  result[x + 1] = vec_fma(result[x + 1], vec_a[1], b_words[y]); \
  result[x + 2] = vec_mul(vec_a[2], b_words[y]);

    BLOCK_PRE(1, 8);
    BLOCK_PRE(2, 16);

    result[5] = kZero;

    vec4_rshift_word(vec_a);

#define BLOCK(x, y)                                             \
  result[x + 0] = vec_fma(result[x + 0], vec_a[0], b_words[y]); \
  result[x + 1] = vec_fma(result[x + 1], vec_a[1], b_words[y]); \
  result[x + 2] = vec_fma(result[x + 2], vec_a[2], b_words[y]); \
  result[x + 3] = vec_fma(result[x + 3], vec_a[3], b_words[y]);

    BLOCK(0, 1);
    BLOCK(1, 9);
    BLOCK(2, 17);

    vec4_rshift_word(vec_a);

    BLOCK(0, 2);
    BLOCK(1, 10);
    BLOCK(2, 18);

    vec4_rshift_word(vec_a);

    BLOCK(0, 3);
    BLOCK(1, 11);
    BLOCK(2, 19);

    vec4_rshift_word(vec_a);

    BLOCK(0, 4);
    BLOCK(1, 12);
    BLOCK(2, 20);

    vec4_rshift_word(vec_a);

    BLOCK(0, 5);
    BLOCK(1, 13);
    BLOCK(2, 21);

    vec4_rshift_word(vec_a);

    BLOCK(0, 6);
    BLOCK(1, 14);
    BLOCK(2, 22);

    vec4_rshift_word(vec_a);

    BLOCK(0, 7);
    BLOCK(1, 15);
    BLOCK(2, 23);

#undef BLOCK
#undef BLOCK_PRE

    memcpy(out, result, sizeof(result));

    return;
  }

  // Karatsuba multiplication.
  // https://en.wikipedia.org/wiki/Karatsuba_algorithm

  // When |n| is odd, the two "halves" will have different lengths. The first is
  // always the smaller.
  const size_t low_len = n / 2;
  const size_t high_len = n - low_len;
  const vec_t *a_high = &a[low_len];
  const vec_t *b_high = &b[low_len];

  // Store a_1 + a_0 in the first half of |out| and b_1 + b_0 in the second
  // half.
  for (size_t i = 0; i < low_len; i++) {
    out[i] = vec_add(a_high[i], a[i]);
    out[high_len + i] = vec_add(b_high[i], b[i]);
  }
  if (high_len != low_len) {
    out[low_len] = a_high[low_len];
    out[high_len + low_len] = b_high[low_len];
  }

  vec_t *const child_scratch = &scratch[2 * high_len];
  // Calculate (a_1 + a_0) × (b_1 + b_0) and write to scratch buffer.
  poly_mul_vec_aux(scratch, child_scratch, out, &out[high_len], high_len);
  // Calculate a_1 × b_1.
  poly_mul_vec_aux(&out[low_len * 2], child_scratch, a_high, b_high, high_len);
  // Calculate a_0 × b_0.
  poly_mul_vec_aux(out, child_scratch, a, b, low_len);

  // Subtract those last two products from the first.
  for (size_t i = 0; i < low_len * 2; i++) {
    scratch[i] = vec_sub(scratch[i], vec_add(out[i], out[low_len * 2 + i]));
  }
  if (low_len != high_len) {
    scratch[low_len * 2] = vec_sub(scratch[low_len * 2], out[low_len * 4]);
    scratch[low_len * 2 + 1] =
        vec_sub(scratch[low_len * 2 + 1], out[low_len * 4 + 1]);
  }

  // Add the middle product into the output.
  for (size_t i = 0; i < high_len * 2; i++) {
    out[low_len + i] = vec_add(out[low_len + i], scratch[i]);
  }
}

// poly_mul_vec sets |*out| to |x|×|y| mod (𝑥^n - 1).
static void poly_mul_vec(struct poly *out, const struct poly *x,
                         const struct poly *y) {
  OPENSSL_memset((uint16_t *)&x->v[N], 0, 3 * sizeof(uint16_t));
  OPENSSL_memset((uint16_t *)&y->v[N], 0, 3 * sizeof(uint16_t));

  OPENSSL_STATIC_ASSERT(sizeof(out->v) == sizeof(vec_t) * VECS_PER_POLY,
                        "struct poly is the wrong size");
  OPENSSL_STATIC_ASSERT(alignof(struct poly) == alignof(vec_t),
                        "struct poly has incorrect alignment");

  vec_t prod[VECS_PER_POLY * 2];
  vec_t scratch[172];
  poly_mul_vec_aux(prod, scratch, (const vec_t *)x->v, (const vec_t *)y->v,
                   VECS_PER_POLY);

  // |prod| needs to be reduced mod (𝑥^n - 1), which just involves adding the
  // upper-half to the lower-half. However, N is 701, which isn't a multiple of
  // the vector size, so the upper-half vectors all have to be shifted before
  // being added to the lower-half.
  vec_t *out_vecs = (vec_t *)out->v;

  for (size_t i = 0; i < VECS_PER_POLY; i++) {
    const vec_t prev = prod[VECS_PER_POLY - 1 + i];
    const vec_t this = prod[VECS_PER_POLY + i];
    out_vecs[i] = vec_add(prod[i], vec_merge_3_5(prev, this));
  }

  OPENSSL_memset(&out->v[N], 0, 3 * sizeof(uint16_t));
}

#endif  // HRSS_HAVE_VECTOR_UNIT

// poly_mul_novec_aux writes the product of |a| and |b| to |out|, using
// |scratch| as scratch space. It'll use Karatsuba if the inputs are large
// enough to warrant it.
static void poly_mul_novec_aux(uint16_t *out, uint16_t *scratch,
                               const uint16_t *a, const uint16_t *b, size_t n) {
  static const size_t kSchoolbookLimit = 64;
  if (n < kSchoolbookLimit) {
    OPENSSL_memset(out, 0, sizeof(uint16_t) * n * 2);
    for (size_t i = 0; i < n; i++) {
      for (size_t j = 0; j < n; j++) {
        out[i + j] += a[i] * b[j];
      }
    }

    return;
  }

  // Karatsuba multiplication.
  // https://en.wikipedia.org/wiki/Karatsuba_algorithm

  // When |n| is odd, the two "halves" will have different lengths. The
  // first is always the smaller.
  const size_t low_len = n / 2;
  const size_t high_len = n - low_len;
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
  poly_mul_novec_aux(scratch, child_scratch, out, &out[high_len], high_len);
  poly_mul_novec_aux(&out[low_len * 2], child_scratch, a_high, b_high,
                     high_len);
  poly_mul_novec_aux(out, child_scratch, a, b, low_len);

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

// poly_mul_novec sets |*out| to |x|×|y| mod (𝑥^n - 1).
static void poly_mul_novec(struct poly *out, const struct poly *x,
                           const struct poly *y) {
  uint16_t prod[2 * N];
  uint16_t scratch[1318];
  poly_mul_novec_aux(prod, scratch, x->v, y->v, N);

  for (size_t i = 0; i < N; i++) {
    out->v[i] = prod[i] + prod[i + N];
  }
  OPENSSL_memset(&out->v[N], 0, 3 * sizeof(uint16_t));
}

// On x86-64, we can use the AVX2 code from [HRSS]. (The authors have given
// explicit permission for this and signed a CLA.) However it's 57KB of object
// code, so it's not used if |OPENSSL_SMALL| is defined.
#if !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_SMALL) && \
    defined(OPENSSL_X86_64) && defined(OPENSSL_LINUX)
// poly_Rq_mul is defined in assembly.
extern void poly_Rq_mul(struct poly *r, const struct poly *a,
                        const struct poly *b);
#endif

// The file cannot be built with -mfpu=neon on ARMv7 because that would enable
// NEON instructions everywhere, not just in functions guarded by a runtime
// check for NEON capability. Therefore on ARMv7, if -mfpu=neon isn't used, a
// version of the vector code that has been precompiled and checked-in as
// assembly sources is used. (For AArch64, NEON is assumed to be provided.)
#if defined(OPENSSL_ARM) && !defined(HRSS_HAVE_VECTOR_UNIT)
// poly_mul_vec is defined in assembly.
extern void poly_mul_vec(struct poly *out, const struct poly *x,
                         const struct poly *y);
#endif

static void poly_mul(struct poly *r, const struct poly *a,
                     const struct poly *b) {
#if !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_SMALL) && \
    defined(OPENSSL_X86_64) && defined(OPENSSL_LINUX)
  const int has_avx2 = (OPENSSL_ia32cap_P[2] & (1 << 5)) != 0;
  if (has_avx2) {
    poly_Rq_mul(r, a, b);
    return;
  }
#endif

#if defined(HRSS_HAVE_VECTOR_UNIT)
  if (vec_capable()) {
    poly_mul_vec(r, a, b);
    return;
  }
#endif

#if defined(OPENSSL_ARM) && !defined(HRSS_HAVE_VECTOR_UNIT)
  // See above about this call.
  if (CRYPTO_is_NEON_capable()) {
    poly_mul_vec(r, a, b);
    return;
  }
#endif

  // Fallback, non-vector case.
  poly_mul_novec(r, a, b);
}

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
  HRSS_poly2_rotr_consttime(&b, rotation);
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

static int poly_unmarshal(struct poly *out, const uint8_t in[POLY_BYTES],
                          int sign_extend) {
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

  if (sign_extend) {
    for (unsigned i = 0; i < N - 1; i++) {
      out->v[i] = (int16_t)(out->v[i] << 3) >> 3;
    }
  }

  // There are four unused bits at the top of the final byte. They are always
  // marshaled as zero by this code by we allow them to take any value when
  // parsing in order to support future extension.

  // Set the final coefficient as specifed in [HRSSNIST] 1.9.2 step 6.
  uint32_t sum = 0;
  for (size_t i = 0; i < N - 1; i++) {
    sum += out->v[i];
  }

  out->v[N - 1] = (uint16_t)(0u - sum);
  return 1;
}

// mod3_from_modQ maps {0, 1, Q-1, 65535} -> {0, 1, 2, 2}.
static uint16_t mod3_from_modQ(uint16_t v) {
  v &= 3;
  return v ^ (v >> 1);
}

// poly_marshal_mod3 marshals |in| to |out| where the coefficients of |in| are
// all in {0, 1, 2} and |in| is mod Φ(N).
static void poly_marshal_mod3(uint8_t out[HRSS_POLY3_BYTES],
                              const struct poly *in) {
  // Only 700 coefficients are marshaled because in[700] must be zero.
  assert(in->v[N - 1] == 0);

  const uint16_t *coeffs = in->v;
  for (size_t i = 0; i < HRSS_POLY3_BYTES; i++) {
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

// public_key_from_external converts an external public key pointer into an
// internal one. Externally the alignment is only specified to be eight bytes
// but we need 16-byte alignment. We could annotate the external struct with
// that alignment but we can only assume that malloced pointers are 8-byte
// aligned in any case. (Even if the underlying malloc returns values with
// 16-byte alignment, |OPENSSL_malloc| will store an 8-byte size prefix and mess
// that up.)
static struct public_key *public_key_from_external(
    struct HRSS_public_key *ext) {
  uintptr_t p = (uintptr_t)ext;
  p = (p + 15) & ~15;
  return (struct public_key *)p;
}

// private_key_from_external does the same thing as |public_key_from_external|,
// but for private keys. See the comment on that function about alignment
// issues.
static struct private_key *private_key_from_external(
    struct HRSS_private_key *ext) {
  uintptr_t p = (uintptr_t)ext;
  p = (p + 15) & ~15;
  return (struct private_key *)p;
}

void HRSS_generate_key(
    struct HRSS_public_key *out_pub, struct HRSS_private_key *out_priv,
    const uint8_t in[HRSS_SAMPLE_BYTES + HRSS_SAMPLE_BYTES + 32]) {
  OPENSSL_STATIC_ASSERT(
      sizeof(struct HRSS_public_key) >= sizeof(struct public_key) + 15,
      "HRSS public key too small");
  OPENSSL_STATIC_ASSERT(
      sizeof(struct HRSS_private_key) >= sizeof(struct private_key) + 15,
      "HRSS private key too small");
  struct public_key *pub = public_key_from_external(out_pub);
  struct private_key *priv = private_key_from_external(out_priv);

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
  const struct public_key *pub =
      public_key_from_external((struct HRSS_public_key *)in_pub);
  struct poly m, r;
  poly_short_sample(&m, in);
  poly_short_sample(&r, in + HRSS_SAMPLE_BYTES);
  owf(out_ciphertext, pub, &m, &r);

  uint8_t m_bytes[HRSS_POLY3_BYTES], r_bytes[HRSS_POLY3_BYTES];
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

void HRSS_decap(uint8_t out_shared_key[HRSS_KEY_BYTES],
                const struct HRSS_public_key *in_pub,
                const struct HRSS_private_key *in_priv,
                const uint8_t *ciphertext, size_t ciphertext_len) {
  const struct public_key *pub =
      public_key_from_external((struct HRSS_public_key *)in_pub);
  const struct private_key *priv =
      private_key_from_external((struct HRSS_private_key *)in_priv);

  // This is HMAC, expanded inline rather than using the |HMAC| function so that
  // we can avoid dealing with possible allocation failures and so keep this
  // function infallible.
  uint8_t masked_key[SHA256_CBLOCK];
  OPENSSL_STATIC_ASSERT(sizeof(priv->hmac_key) <= sizeof(masked_key),
                        "HRSS HMAC key larger than SHA-256 block size");
  for (size_t i = 0; i < sizeof(priv->hmac_key); i++) {
    masked_key[i] = priv->hmac_key[i] ^ 0x36;
  }
  OPENSSL_memset(masked_key + sizeof(priv->hmac_key), 0x36,
                 sizeof(masked_key) - sizeof(priv->hmac_key));

  SHA256_CTX hash_ctx;
  SHA256_Init(&hash_ctx);
  SHA256_Update(&hash_ctx, masked_key, sizeof(masked_key));
  SHA256_Update(&hash_ctx, ciphertext, ciphertext_len);
  uint8_t inner_digest[SHA256_DIGEST_LENGTH];
  SHA256_Final(inner_digest, &hash_ctx);

  for (size_t i = 0; i < sizeof(priv->hmac_key); i++) {
    masked_key[i] ^= (0x5c ^ 0x36);
  }
  OPENSSL_memset(masked_key + sizeof(priv->hmac_key), 0x5c,
                 sizeof(masked_key) - sizeof(priv->hmac_key));

  SHA256_Init(&hash_ctx);
  SHA256_Update(&hash_ctx, masked_key, sizeof(masked_key));
  SHA256_Update(&hash_ctx, inner_digest, sizeof(inner_digest));
  OPENSSL_STATIC_ASSERT(HRSS_KEY_BYTES == SHA256_DIGEST_LENGTH,
                        "HRSS shared key length incorrect");
  SHA256_Final(out_shared_key, &hash_ctx);

  // If the ciphertext is publicly invalid then a random shared key is still
  // returned to simply the logic of the caller, but this path is not constant
  // time.
  struct poly c;
  if (ciphertext_len != POLY_BYTES + 32 || !poly_unmarshal(&c, ciphertext, 1)) {
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

  uint8_t m_bytes[HRSS_POLY3_BYTES];
  uint8_t r_bytes[HRSS_POLY3_BYTES];
  poly_marshal_mod3(m_bytes, &m);
  poly_marshal_mod3(r_bytes, &c);

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

void HRSS_marshal_public_key(uint8_t out[HRSS_PUBLIC_KEY_BYTES],
                             const struct HRSS_public_key *in_pub) {
  const struct public_key *pub =
      public_key_from_external((struct HRSS_public_key *)in_pub);
  poly_marshal(out, &pub->ph);
}

int HRSS_parse_public_key(struct HRSS_public_key *out,
                          const uint8_t in[HRSS_PUBLIC_KEY_BYTES]) {
  struct public_key *pub = public_key_from_external(out);
  if (!poly_unmarshal(&pub->ph, in, 1)) {
    return 0;
  }
  OPENSSL_memset(&pub->ph.v[N], 0, 3 * sizeof(uint16_t));
  return 1;
}
