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

#include <gtest/gtest.h>

#include <openssl/cpu.h>
#include <openssl/hrss.h>
#include <openssl/rand.h>

#include "../test/abi_test.h"
#include "../test/test_util.h"
#include "internal.h"


// poly3_rand sets |r| to a random value (albeit with bias).
static void poly3_rand(poly3 *p) {
  RAND_bytes(reinterpret_cast<uint8_t *>(p), sizeof(poly3));
  p->s.v[WORDS_PER_POLY - 1] &= (UINT64_C(1) << BITS_IN_LAST_WORD) - 1;
  p->a.v[WORDS_PER_POLY - 1] &= (UINT64_C(1) << BITS_IN_LAST_WORD) - 1;
  // (s, a) = (1, 0) is invalid. Map those to -1.
  for (size_t j = 0; j < WORDS_PER_POLY; j++) {
    p->a.v[j] |= p->s.v[j];
  }
}

// poly3_word_add sets (|s1|, |a1|) += (|s2|, |a2|).
static void poly3_word_add(crypto_word_t *s1, crypto_word_t *a1,
                           const crypto_word_t s2, const crypto_word_t a2) {
  const crypto_word_t t = *s1 ^ a2;
  *s1 = t & (s2 ^ *a1);
  *a1 = (*a1 ^ a2) | (t ^ s2);
}

TEST(HRSS, Poly3Invert) {
  poly3 p, inverse, result;
  memset(&p, 0, sizeof(p));
  memset(&inverse, 0, sizeof(inverse));
  memset(&result, 0, sizeof(result));

  p.s.v[0] = 0;
  p.a.v[0] = 1;
  for (size_t i = 0; i < N - 1; i++) {
    SCOPED_TRACE(i);
    poly3 r;
    OPENSSL_memset(&r, 0, sizeof(r));
    r.a.v[i / BITS_PER_WORD] = (UINT64_C(1) << (i % BITS_PER_WORD));
    HRSS_poly3_invert(&inverse, &r);
    HRSS_poly3_mul(&result, &inverse, &r);
    // r×r⁻¹ = 1, and |p| contains 1.
    EXPECT_EQ(
        Bytes(reinterpret_cast<const uint8_t *>(&p), sizeof(p)),
        Bytes(reinterpret_cast<const uint8_t *>(&result), sizeof(result)));
  }

  // The inverse of -1 is -1.
  p.s.v[0] = 1;
  p.a.v[0] = 1;
  HRSS_poly3_invert(&inverse, &p);
  EXPECT_EQ(Bytes(reinterpret_cast<const uint8_t*>(&p), sizeof(p)),
            Bytes(reinterpret_cast<const uint8_t*>(&inverse), sizeof(inverse)));

  // The inverse of 1 is 1.
  p.s.v[0] = 0;
  p.a.v[0] = 1;
  HRSS_poly3_invert(&inverse, &p);
  EXPECT_EQ(Bytes(reinterpret_cast<const uint8_t*>(&p), sizeof(p)),
            Bytes(reinterpret_cast<const uint8_t*>(&inverse), sizeof(inverse)));

  for (size_t i = 0; i < 500; i++) {
    poly3 r;
    poly3_rand(&r);
    // Drop the term at x^700 because |HRSS_poly3_invert| only handles reduced
    // inputs.
    r.s.v[WORDS_PER_POLY - 1] &= (UINT64_C(1) << (BITS_IN_LAST_WORD - 1)) - 1;
    r.a.v[WORDS_PER_POLY - 1] &= (UINT64_C(1) << (BITS_IN_LAST_WORD - 1)) - 1;
    HRSS_poly3_invert(&inverse, &r);
    HRSS_poly3_mul(&result, &inverse, &r);
    // r×r⁻¹ = 1, and |p| contains 1.
    EXPECT_EQ(
        Bytes(reinterpret_cast<const uint8_t *>(&p), sizeof(p)),
        Bytes(reinterpret_cast<const uint8_t *>(&result), sizeof(result)));
  }
}

TEST(HRSS, Poly3UnreducedInput) {
  // Check that |poly3_mul| works correctly with inputs that aren't reduced mod
  // Φ(N).
  poly3 r, inverse, result, one;
  poly3_rand(&r);
  // Drop the term at x^700 because |HRSS_poly3_invert| only handles reduced
  // inputs.
  r.s.v[WORDS_PER_POLY - 1] &= (UINT64_C(1) << (BITS_IN_LAST_WORD - 1)) - 1;
  r.a.v[WORDS_PER_POLY - 1] &= (UINT64_C(1) << (BITS_IN_LAST_WORD - 1)) - 1;
  HRSS_poly3_invert(&inverse, &r);
  HRSS_poly3_mul(&result, &inverse, &r);

  memset(&one, 0, sizeof(one));
  one.a.v[0] = 1;
  EXPECT_EQ(Bytes(reinterpret_cast<const uint8_t *>(&one), sizeof(one)),
            Bytes(reinterpret_cast<const uint8_t *>(&result), sizeof(result)));

  // |r| is reduced mod Φ(N), so add x^701 - 1 and recompute to ensure that we
  // get the same answer. (Since (x^701 - 1) ≡ 0 mod Φ(N).)
  poly3_word_add(&r.s.v[0], &r.a.v[0], 1, 1);
  poly3_word_add(&r.s.v[WORDS_PER_POLY - 1], &r.a.v[WORDS_PER_POLY - 1], 0,
                 UINT64_C(1) << BITS_IN_LAST_WORD);

  HRSS_poly3_mul(&result, &inverse, &r);
  EXPECT_EQ(Bytes(reinterpret_cast<const uint8_t *>(&one), sizeof(one)),
            Bytes(reinterpret_cast<const uint8_t *>(&result), sizeof(result)));

  // Check that x^700 × 1 gives -x^699 - x^698 … -1.
  poly3 x700;
  memset(&x700, 0, sizeof(x700));
  x700.a.v[WORDS_PER_POLY-1] = UINT64_C(1) << (BITS_IN_LAST_WORD - 1);
  HRSS_poly3_mul(&result, &one, &x700);

  for (size_t i = 0; i < WORDS_PER_POLY-1; i++) {
    EXPECT_EQ(CONSTTIME_TRUE_W, result.s.v[i]);
    EXPECT_EQ(CONSTTIME_TRUE_W, result.a.v[i]);
  }
  EXPECT_EQ((UINT64_C(1) << (BITS_IN_LAST_WORD - 1)) - 1,
            result.s.v[WORDS_PER_POLY - 1]);
  EXPECT_EQ(result.s.v[WORDS_PER_POLY - 1], result.a.v[WORDS_PER_POLY - 1]);
}

TEST(HRSS, Basic) {
  uint8_t generate_key_entropy[HRSS_GENERATE_KEY_BYTES];
  for (unsigned i = 0; i < sizeof(generate_key_entropy); i++) {
    generate_key_entropy[i] = i;
  }

  HRSS_public_key pub;
  HRSS_private_key priv;
  ASSERT_TRUE(HRSS_generate_key(&pub, &priv, generate_key_entropy));

  uint8_t encap_entropy[HRSS_ENCAP_BYTES];
  for (unsigned i = 0; i < sizeof(encap_entropy); i++) {
    encap_entropy[i] = i;
  }

  HRSS_public_key pub2;
  uint8_t pub_bytes[HRSS_PUBLIC_KEY_BYTES];
  HRSS_marshal_public_key(pub_bytes, &pub);
  ASSERT_TRUE(HRSS_parse_public_key(&pub2, pub_bytes));

  uint8_t ciphertext[HRSS_CIPHERTEXT_BYTES];
  uint8_t shared_key[HRSS_KEY_BYTES];
  ASSERT_TRUE(HRSS_encap(ciphertext, shared_key, &pub2, encap_entropy));

  uint8_t shared_key2[HRSS_KEY_BYTES];
  ASSERT_TRUE(HRSS_decap(shared_key2, &priv, ciphertext, sizeof(ciphertext)));

  EXPECT_EQ(Bytes(shared_key), Bytes(shared_key2));
}

TEST(HRSS, Random) {
  for (unsigned i = 0; i < 10; i++) {
    uint8_t generate_key_entropy[HRSS_GENERATE_KEY_BYTES];
    RAND_bytes(generate_key_entropy, sizeof(generate_key_entropy));
    SCOPED_TRACE(Bytes(generate_key_entropy));

    HRSS_public_key pub;
    HRSS_private_key priv;
    ASSERT_TRUE(HRSS_generate_key(&pub, &priv, generate_key_entropy));

    for (unsigned j = 0; j < 10; j++) {
      uint8_t encap_entropy[HRSS_ENCAP_BYTES];
      RAND_bytes(encap_entropy, sizeof(encap_entropy));
      SCOPED_TRACE(Bytes(encap_entropy));

      uint8_t ciphertext[HRSS_CIPHERTEXT_BYTES];
      uint8_t shared_key[HRSS_KEY_BYTES];
      ASSERT_TRUE(HRSS_encap(ciphertext, shared_key, &pub, encap_entropy));

      uint8_t shared_key2[HRSS_KEY_BYTES];
      ASSERT_TRUE(
          HRSS_decap(shared_key2, &priv, ciphertext, sizeof(ciphertext)));
      EXPECT_EQ(Bytes(shared_key), Bytes(shared_key2));

      uint32_t offset;
      RAND_bytes((uint8_t*) &offset, sizeof(offset));
      uint8_t bit;
      RAND_bytes(&bit, sizeof(bit));
      ciphertext[offset % sizeof(ciphertext)] ^= (1 << (bit & 7));
      ASSERT_TRUE(
          HRSS_decap(shared_key2, &priv, ciphertext, sizeof(ciphertext)));
      EXPECT_NE(Bytes(shared_key), Bytes(shared_key2));
    }
  }
}

TEST(HRSS, Golden) {
  uint8_t generate_key_entropy[HRSS_GENERATE_KEY_BYTES];
  for (unsigned i = 0; i < HRSS_SAMPLE_BYTES; i++) {
    generate_key_entropy[i] = i;
  }
  for (unsigned i = HRSS_SAMPLE_BYTES; i < 2 * HRSS_SAMPLE_BYTES; i++) {
    generate_key_entropy[i] = 2 + i;
  }
  for (unsigned i = 2 * HRSS_SAMPLE_BYTES; i < sizeof(generate_key_entropy);
       i++) {
    generate_key_entropy[i] = 4 + i;
  }

  HRSS_public_key pub;
  HRSS_private_key priv;
  OPENSSL_memset(&pub, 0, sizeof(pub));
  OPENSSL_memset(&priv, 0, sizeof(priv));
  ASSERT_TRUE(HRSS_generate_key(&pub, &priv, generate_key_entropy));

  static const uint8_t kExpectedPub[HRSS_PUBLIC_KEY_BYTES] = {
      0x4a, 0x21, 0x39, 0x7c, 0xb4, 0xa6, 0x58, 0x15, 0x35, 0x77, 0xe4, 0x2a,
      0x02, 0x79, 0xc0, 0x02, 0xe2, 0x21, 0x27, 0x5f, 0x49, 0xc7, 0x2c, 0x14,
      0xb6, 0xe0, 0x67, 0xc2, 0xc7, 0x09, 0x62, 0x0c, 0xe5, 0x23, 0x9c, 0x40,
      0xd7, 0x7e, 0xf5, 0x55, 0x5a, 0xa2, 0xd0, 0x9f, 0xd3, 0x8c, 0x67, 0x7b,
      0x48, 0xa4, 0x53, 0x8d, 0x39, 0xb1, 0xcc, 0x99, 0x29, 0xf7, 0x83, 0xbf,
      0x6f, 0x9b, 0x16, 0x73, 0x23, 0xcc, 0xc3, 0x86, 0x98, 0xb1, 0x7c, 0x53,
      0xb1, 0xf5, 0xf4, 0xdd, 0xc8, 0x97, 0x5e, 0xd3, 0x6d, 0x63, 0xce, 0xf3,
      0xa2, 0xf6, 0xef, 0x94, 0xed, 0x4a, 0x3e, 0xe6, 0x4b, 0xa2, 0xfb, 0x87,
      0xa3, 0xbc, 0x65, 0x1c, 0x17, 0x64, 0x25, 0xa7, 0xb4, 0xa1, 0xe6, 0x84,
      0x06, 0x72, 0x0c, 0x28, 0xe8, 0xfc, 0xaa, 0xca, 0xf8, 0x20, 0x79, 0x89,
      0xa9, 0xf0, 0x60, 0xdf, 0xd6, 0xd4, 0xe0, 0xaf, 0x99, 0x54, 0x21, 0xaf,
      0x76, 0xd5, 0x9a, 0x31, 0x80, 0xea, 0x7f, 0x03, 0x6c, 0x14, 0x74, 0x06,
      0x9c, 0x93, 0xe3, 0x93, 0xcc, 0x46, 0x4d, 0x82, 0xda, 0xdf, 0x67, 0xe9,
      0x6d, 0x58, 0x2b, 0x49, 0xf3, 0x10, 0x71, 0xa0, 0xc5, 0xec, 0xa0, 0x29,
      0xd7, 0x7c, 0x43, 0xd5, 0x05, 0x7e, 0x14, 0x8c, 0x39, 0x28, 0xf9, 0x46,
      0x3d, 0xc1, 0x10, 0x6c, 0x2f, 0xaa, 0xca, 0x11, 0x87, 0x6a, 0xe2, 0xb1,
      0xf6, 0x31, 0x76, 0xb0, 0xdc, 0x30, 0x8a, 0x97, 0x7d, 0xdc, 0xe4, 0xd1,
      0x18, 0xe9, 0x03, 0x91, 0xf5, 0xd2, 0x94, 0x4d, 0x71, 0xf7, 0x35, 0xc8,
      0x3e, 0x46, 0xaf, 0xa3, 0xeb, 0x35, 0x07, 0x01, 0x77, 0xc5, 0x58, 0xca,
      0x82, 0x67, 0x3e, 0x4f, 0x01, 0x88, 0xa4, 0xa0, 0xea, 0x0a, 0xb7, 0x13,
      0x06, 0xbe, 0xb6, 0x61, 0xa4, 0xa2, 0x28, 0xe2, 0x32, 0xcf, 0x25, 0x46,
      0xcf, 0xce, 0xf5, 0x57, 0x9b, 0x74, 0x8f, 0xfd, 0xbc, 0xfa, 0x3a, 0xa2,
      0x18, 0x22, 0xf1, 0xb1, 0x43, 0x12, 0xe8, 0xe2, 0xe3, 0x06, 0xe6, 0x1c,
      0xa7, 0x76, 0x2d, 0x0d, 0xe5, 0x5f, 0xbd, 0x8f, 0xa0, 0x95, 0xcd, 0xe9,
      0x28, 0xdb, 0xcc, 0xe5, 0x66, 0x33, 0xd4, 0x4b, 0xf9, 0x0c, 0x42, 0x9b,
      0x27, 0xee, 0x11, 0xd0, 0xe3, 0x0b, 0x9d, 0xce, 0x2c, 0x91, 0x7a, 0x0e,
      0xb8, 0xde, 0x31, 0x73, 0x86, 0x8e, 0x34, 0x59, 0x93, 0x2e, 0x37, 0x9d,
      0xc2, 0x3e, 0x89, 0x0b, 0x47, 0xff, 0xa6, 0x55, 0x21, 0xe6, 0x4f, 0x72,
      0x7c, 0xcc, 0xe5, 0xb8, 0x18, 0x2c, 0x10, 0xcb, 0xce, 0x48, 0xa5, 0xc5,
      0x26, 0xb6, 0x19, 0x76, 0xc5, 0x38, 0xf0, 0x38, 0x72, 0xec, 0x22, 0xf9,
      0x25, 0xde, 0x1c, 0x0c, 0x1b, 0x3e, 0x43, 0xc5, 0x5c, 0x8c, 0xdb, 0xf1,
      0x42, 0x66, 0xbc, 0xdf, 0xa0, 0x82, 0x4b, 0xec, 0xe1, 0x50, 0x42, 0x57,
      0x84, 0x60, 0xfd, 0x89, 0x12, 0x1b, 0xf6, 0xf9, 0x4d, 0x0d, 0x16, 0xe8,
      0xa4, 0xe2, 0x67, 0x2c, 0x8f, 0x22, 0xea, 0xba, 0x46, 0x34, 0xce, 0x97,
      0x8b, 0x4c, 0x38, 0x0e, 0x16, 0x82, 0xb6, 0xf3, 0x34, 0x38, 0x07, 0x87,
      0x73, 0x2a, 0x3d, 0x80, 0x56, 0x4b, 0x85, 0x67, 0xca, 0x2a, 0x19, 0xb6,
      0xb6, 0x2c, 0xfe, 0xd8, 0x02, 0xe5, 0xad, 0xd0, 0x61, 0x79, 0x73, 0xab,
      0xda, 0x3b, 0xa4, 0x51, 0xb3, 0xf7, 0x85, 0x99, 0xb2, 0xd0, 0x64, 0x97,
      0xb7, 0x3c, 0x0e, 0x58, 0xdf, 0xd2, 0x98, 0x98, 0x18, 0x1a, 0xf5, 0x59,
      0xcd, 0xc5, 0x48, 0x17, 0x10, 0x9f, 0xd8, 0x19, 0xbd, 0xd0, 0x42, 0x71,
      0x1c, 0x30, 0xc6, 0x76, 0xe9, 0xb0, 0xee, 0xf5, 0x38, 0x05, 0xbe, 0x9b,
      0x6c, 0x0d, 0xb0, 0xd0, 0xda, 0x1c, 0x89, 0xbd, 0x40, 0x5d, 0xc2, 0x5a,
      0xbe, 0x83, 0xa6, 0xb5, 0x47, 0xa7, 0xf8, 0xb9, 0xbf, 0xa2, 0x65, 0x17,
      0x1e, 0xd8, 0x28, 0x42, 0xbe, 0xb0, 0x35, 0xf6, 0x7b, 0x88, 0x38, 0xbe,
      0xf5, 0xb5, 0x1b, 0x63, 0x7a, 0x83, 0x92, 0x0d, 0x64, 0xad, 0x92, 0x59,
      0x97, 0x55, 0x5c, 0x60, 0xab, 0x48, 0x8e, 0x23, 0x27, 0x22, 0x75, 0x3b,
      0x7c, 0x9c, 0x69, 0x13, 0x52, 0x6b, 0xae, 0xfd, 0x38, 0xe5, 0x4b, 0x36,
      0x78, 0x55, 0x92, 0xb5, 0x8f, 0x25, 0xde, 0x0e, 0x93, 0xe3, 0x1d, 0x83,
      0x62, 0x05, 0x6a, 0x5a, 0xff, 0x7f, 0x77, 0xf7, 0x1b, 0xfc, 0x21, 0x45,
      0xf7, 0xb8, 0xfa, 0xcb, 0x00, 0x5e, 0x85, 0xf9, 0x2f, 0x15, 0x2f, 0xcf,
      0x17, 0x9e, 0x84, 0xf6, 0xf5, 0x15, 0x6e, 0xdd, 0xb4, 0x73, 0x44, 0xc2,
      0x2c, 0x74, 0xae, 0x27, 0x5f, 0x19, 0xe7, 0x51, 0x61, 0xc1, 0x82, 0xce,
      0xf1, 0x5b, 0xa0, 0x6f, 0x0b, 0x13, 0x10, 0x68, 0xb7, 0xee, 0xfb, 0x8a,
      0x85, 0xe2, 0xd6, 0x17, 0x55, 0x26, 0xa5, 0xc5, 0xb3, 0x94, 0x45, 0xdf,
      0x49, 0xe6, 0x50, 0xf8, 0x99, 0xd8, 0x3c, 0xcb, 0x94, 0x80, 0x67, 0x3b,
      0x73, 0xac, 0xf6, 0x46, 0x31, 0x63, 0xb3, 0x1b, 0x47, 0xce, 0x40, 0x3f,
      0x8c, 0xd0, 0x82, 0xc4, 0x79, 0x3a, 0x7c, 0x48, 0x10, 0xe3, 0x97, 0x98,
      0xdc, 0x0b, 0x62, 0x42, 0xfa, 0x26, 0x05, 0xf6, 0x8c, 0x32, 0xa9, 0xb6,
      0x2c, 0x4f, 0x85, 0xd2, 0x9b, 0xf3, 0x89, 0x1f, 0x91, 0xca, 0x12, 0x3d,
      0xe2, 0xa8, 0x0b, 0xca, 0x64, 0x28, 0x0e, 0xa7, 0xfd, 0xd8, 0xa3, 0xcb,
      0x0a, 0xd9, 0x97, 0x2d, 0xc3, 0xf2, 0x39, 0x74, 0xdb, 0xe3, 0x9a, 0x87,
      0x1a, 0xe0, 0x33, 0xe3, 0x92, 0xe8, 0xde, 0xb5, 0x08, 0x28, 0xcb, 0xd7,
      0xb6, 0x79, 0xec, 0x71, 0xcc, 0xe5, 0xd1, 0x4b, 0x89, 0x96, 0x5f, 0xfa,
      0xfd, 0x4b, 0xd0, 0xa8, 0x66, 0x0d, 0xb4, 0xa7, 0x51, 0x56, 0xbc, 0xa7,
      0x74, 0x07, 0x7f, 0xae, 0x0e, 0xf6, 0x9c, 0x13, 0xd9, 0xf2, 0xed, 0x12,
      0xa9, 0x87, 0x3e, 0xb7, 0x9d, 0x53, 0x8a, 0x82, 0x2d, 0x03, 0x2f, 0xac,
      0x94, 0x84, 0x95, 0x00, 0x29, 0x09, 0x01, 0x38, 0x62, 0xff, 0xaf, 0xfd,
      0x10, 0x2b, 0x31, 0x03, 0xb2, 0x4f, 0x51, 0xfb, 0x76, 0x27, 0x1e, 0x25,
      0x82, 0x79, 0x65, 0x69, 0xfa, 0x24, 0xaf, 0xcb, 0xe8, 0x40, 0x8d, 0x7d,
      0xd2, 0x9a, 0x12, 0x69, 0x2f, 0xe4, 0xce, 0x99, 0x98, 0x4f, 0x6c, 0x46,
      0xfd, 0x63, 0x40, 0x50, 0xef, 0x22, 0x02, 0x68, 0x2e, 0x53, 0xbb, 0x00,
      0xa3, 0x65, 0x61, 0x3e, 0x97, 0xd4, 0x5f, 0xa2, 0xc1, 0x66, 0xcd, 0x04,
      0xdc, 0xda, 0x55, 0x10, 0x28, 0x0d, 0x40, 0x11, 0xe6, 0x68, 0xed, 0x68,
      0x38, 0x7d, 0x20, 0xc3, 0x97, 0x9d, 0xcb, 0x6e, 0x30, 0xfc, 0xbe, 0x63,
      0xe7, 0x72, 0x47, 0x05, 0xf5, 0x0b, 0x7e, 0x66, 0x3b, 0xc5, 0x3a, 0x85,
      0x5a, 0xa3, 0xc5, 0x72, 0x9d, 0xb9, 0xc1, 0xb4, 0x80, 0x98, 0x6e, 0x40,
      0x86, 0xc9, 0xcb, 0xa3, 0xab, 0x77, 0xc2, 0x56, 0xfc, 0xcb, 0x6e, 0x12,
      0xf5, 0x63, 0x62, 0xf8, 0xff, 0x91, 0x15, 0xa7, 0xa1, 0x5e, 0xb6, 0xee,
      0x69, 0x4d, 0x5b, 0x5f, 0x4e, 0xfa, 0xd3, 0x61, 0xca, 0xec, 0x14, 0xfd,
      0xd9, 0x10, 0xf5, 0x4a, 0x05, 0x5f, 0x29, 0xcb, 0x77, 0x2c, 0x2d, 0xe2,
      0x90, 0x67, 0x62, 0x78, 0x75, 0xa9, 0x4e, 0x20, 0x00, 0x0c, 0x91, 0x84,
      0xba, 0xed, 0x1c, 0xce, 0xbd, 0x57, 0x4f, 0xa5, 0x2f, 0x59, 0x6c, 0x4c,
      0xdf, 0x5f, 0xaa, 0x32, 0xf0, 0x86, 0x09, 0x15, 0x36, 0xc6, 0xe6, 0x6a,
      0x24, 0xb4, 0xb3, 0x09, 0xdd, 0x32, 0xc5, 0x95, 0xac, 0x60, 0xb5, 0x09,
      0x97, 0x36, 0xa1, 0x3c, 0x8f, 0x0e, 0x90, 0x8e, 0xcd, 0xd0, 0x49, 0x75,
      0xf7, 0xf3, 0x80, 0x80, 0xcb, 0x1f, 0xee, 0xf2, 0x6a, 0x2f, 0x19, 0x8c,
      0xba, 0x10, 0x00, 0xda, 0x13, 0xef, 0x10, 0x2b, 0xb7, 0xef, 0xfd, 0xd1,
      0xe0, 0x7c, 0xf8, 0x46, 0x01, 0x69, 0x9b, 0x99, 0x80, 0x51, 0x1f, 0x74,
      0x3b, 0x67, 0x93, 0x18, 0x5e, 0xd4, 0x34, 0x6c, 0x81, 0x76, 0x02, 0xef,
      0x91, 0xa4, 0x22, 0x2a, 0x23, 0x1b, 0x58, 0x43, 0x75, 0x65, 0x13, 0x87,
      0x98, 0x60, 0x14, 0x25, 0x28, 0x67, 0xa3, 0x34, 0x8c, 0xe0, 0xd5, 0xd3,
      0x51, 0x33, 0x68, 0xff, 0x65, 0x59, 0x5a, 0xa7, 0xb2, 0x6b, 0x01, 0xad,
      0x70, 0x06, 0x73, 0x01, 0x51, 0x1b, 0xe1, 0xec, 0x28, 0x2f, 0x8a, 0x85,
      0x5a, 0x10, 0xd0, 0x0e, 0x6b, 0x35, 0x45, 0x2e, 0x61, 0xdd, 0x77, 0x20,
      0xb1, 0x35, 0x3b, 0xa8, 0xdd, 0x8a, 0xe2, 0x15, 0x79, 0x07,
  };
  uint8_t pub_bytes[HRSS_PUBLIC_KEY_BYTES];
  HRSS_marshal_public_key(pub_bytes, &pub);
  EXPECT_EQ(Bytes(pub_bytes), Bytes(kExpectedPub));

  uint8_t encap_entropy[HRSS_ENCAP_BYTES];
  for (size_t i = 0; i < sizeof(encap_entropy); i++) {
    encap_entropy[i] = 31 + i;
  }
  uint8_t ciphertext[HRSS_CIPHERTEXT_BYTES];
  uint8_t shared_key[HRSS_KEY_BYTES];
  ASSERT_TRUE(HRSS_encap(ciphertext, shared_key, &pub, encap_entropy));

  static const uint8_t kExpectedCiphertext[HRSS_CIPHERTEXT_BYTES] = {
      0xe0, 0xc0, 0x77, 0xeb, 0x7a, 0x48, 0x7d, 0x74, 0x4e, 0x4f, 0x6d, 0xb9,
      0x5c, 0x18, 0xe9, 0x5b, 0x47, 0x6c, 0x78, 0x9d, 0x98, 0x02, 0x84, 0x9f,
      0xf2, 0x45, 0x43, 0x86, 0x0e, 0xc6, 0x93, 0x48, 0xd8, 0x20, 0xff, 0x82,
      0x38, 0x9e, 0x78, 0xb4, 0x2c, 0xb3, 0x42, 0xe4, 0xb3, 0xab, 0xdf, 0xed,
      0x65, 0x24, 0x0c, 0xa5, 0x95, 0x2c, 0xbf, 0x4c, 0x28, 0xfc, 0xb8, 0xe7,
      0xc6, 0xbc, 0x76, 0xa0, 0xf5, 0x3f, 0x29, 0x73, 0x23, 0xf1, 0x6c, 0x10,
      0x7c, 0x08, 0x8e, 0x16, 0x3a, 0xda, 0x17, 0xa3, 0x0d, 0x46, 0x44, 0xee,
      0x6f, 0x70, 0xf1, 0x88, 0x51, 0x35, 0x33, 0x91, 0x76, 0xeb, 0x98, 0xc1,
      0x04, 0xdb, 0x97, 0xab, 0x88, 0xb9, 0x04, 0x87, 0xd9, 0xb8, 0x34, 0xd3,
      0x38, 0xe7, 0x90, 0x05, 0x2e, 0x45, 0xe0, 0xac, 0x36, 0x0c, 0x59, 0x58,
      0xb1, 0xf5, 0x65, 0x6d, 0x28, 0x1a, 0x39, 0xd9, 0xd2, 0x83, 0x17, 0xee,
      0xeb, 0x6f, 0x7d, 0x29, 0x3c, 0x79, 0xcf, 0x48, 0xf1, 0x6d, 0x35, 0xc2,
      0x8c, 0xe8, 0x67, 0x18, 0xcc, 0x9d, 0x9b, 0x8d, 0x07, 0x7a, 0x4e, 0x56,
      0xa8, 0x00, 0x2e, 0x67, 0x67, 0xbb, 0xc1, 0xda, 0x4a, 0x7b, 0x9f, 0xa6,
      0x4a, 0x5c, 0x40, 0xcc, 0xe4, 0xdd, 0xf5, 0xc0, 0x44, 0xfe, 0xa5, 0xa2,
      0x1c, 0xdc, 0xf2, 0x31, 0xf4, 0x01, 0x1f, 0x69, 0x15, 0x7e, 0x8c, 0x54,
      0xb6, 0x47, 0x0c, 0x1d, 0x9f, 0x1a, 0xfa, 0xf7, 0x46, 0xa3, 0xcb, 0x34,
      0x2c, 0x18, 0x45, 0x65, 0xc4, 0xf2, 0x0e, 0xf8, 0xc7, 0x96, 0x1d, 0x29,
      0x5c, 0x90, 0xd3, 0xdf, 0xb2, 0x8e, 0x21, 0xf9, 0x15, 0x40, 0x7e, 0xd3,
      0x84, 0x52, 0x1d, 0xd9, 0xee, 0xed, 0xe8, 0x71, 0x1c, 0xdb, 0x48, 0xf5,
      0x20, 0x82, 0xc4, 0x61, 0xfd, 0x6d, 0x71, 0x9f, 0xd8, 0x03, 0x90, 0x8e,
      0xfc, 0xed, 0x4d, 0xab, 0x6e, 0xb2, 0xe9, 0x66, 0xfd, 0xcc, 0x3a, 0xa3,
      0x99, 0x53, 0x35, 0x76, 0xea, 0x08, 0x88, 0xba, 0xf0, 0xb7, 0x53, 0xf3,
      0x4c, 0x1a, 0x8f, 0x7f, 0xe4, 0x1b, 0x8b, 0xfc, 0x99, 0x3e, 0x4c, 0xa9,
      0xd9, 0x17, 0x10, 0x64, 0x60, 0xfd, 0x81, 0x76, 0xe6, 0x37, 0xb0, 0xe3,
      0x3e, 0xc0, 0xf7, 0x06, 0x7e, 0x34, 0xa5, 0xf4, 0xb9, 0x5f, 0x66, 0xe6,
      0x81, 0xc8, 0x5e, 0xb2, 0x26, 0x6b, 0x8c, 0xad, 0xd0, 0x94, 0x01, 0x22,
      0xf6, 0xbe, 0x1a, 0x0b, 0x34, 0xfc, 0x33, 0xc0, 0x84, 0xa5, 0xe0, 0x12,
      0x8a, 0x08, 0xae, 0x8a, 0xaf, 0x55, 0x0c, 0x34, 0x4b, 0x2b, 0xdd, 0xa3,
      0x7c, 0xc0, 0xed, 0xe8, 0x8d, 0x98, 0x47, 0x7c, 0x81, 0x25, 0x1b, 0x9f,
      0x08, 0x26, 0x9d, 0xfc, 0x19, 0x8e, 0x39, 0xc4, 0x1a, 0x3c, 0x42, 0x70,
      0x49, 0x37, 0x57, 0x87, 0x0f, 0x76, 0xb1, 0xc4, 0xbe, 0x25, 0x5e, 0x1c,
      0x06, 0x57, 0xc6, 0x88, 0x34, 0x28, 0xdf, 0x60, 0x33, 0x09, 0xc5, 0xcc,
      0xf4, 0xc4, 0x33, 0x85, 0x8b, 0x48, 0xe8, 0x27, 0xb7, 0x72, 0x22, 0x44,
      0xff, 0xe7, 0x89, 0xf9, 0x71, 0x99, 0xed, 0x62, 0x47, 0xb0, 0x22, 0x9e,
      0xa6, 0x7c, 0xaf, 0xa9, 0x98, 0x2b, 0x5c, 0x8a, 0x42, 0x34, 0x77, 0xa3,
      0xc8, 0x13, 0x1e, 0xcf, 0x32, 0xa7, 0x70, 0xa8, 0xad, 0xc1, 0x66, 0x5c,
      0x8f, 0xaf, 0x14, 0x6d, 0xc4, 0x45, 0x05, 0xcd, 0xcb, 0x80, 0xfa, 0x0e,
      0xa6, 0xca, 0x72, 0x86, 0xd2, 0xb7, 0x39, 0x26, 0x77, 0xf8, 0x14, 0xd0,
      0xcd, 0xdd, 0xf7, 0xdc, 0xda, 0x25, 0x8e, 0x3c, 0x21, 0xfd, 0xef, 0x92,
      0xee, 0x52, 0xf7, 0xc3, 0xc7, 0xe2, 0x2d, 0x1c, 0x57, 0x5a, 0xba, 0xd8,
      0xaa, 0x0d, 0x09, 0xa7, 0xb3, 0xcc, 0xa1, 0x5d, 0xdb, 0x04, 0x21, 0x82,
      0xef, 0xba, 0xc2, 0xc8, 0x54, 0xb1, 0xbe, 0xd7, 0x2a, 0x91, 0xd8, 0xeb,
      0x72, 0x54, 0xc1, 0x74, 0x24, 0x24, 0x5a, 0x03, 0xf7, 0xcd, 0xab, 0x91,
      0xd1, 0x63, 0xf1, 0x60, 0x9f, 0x22, 0x07, 0xad, 0x10, 0x2b, 0x97, 0x1c,
      0x6f, 0xce, 0xc0, 0x29, 0xc2, 0xb2, 0xb8, 0x1b, 0xbd, 0x14, 0xc8, 0xb9,
      0x80, 0x66, 0xc1, 0x86, 0xfc, 0x93, 0x5f, 0x6e, 0x0b, 0x7a, 0x7b, 0x8e,
      0x42, 0x8c, 0x08, 0xd1, 0x60, 0xb9, 0xf8, 0x66, 0x24, 0x7d, 0x88, 0x58,
      0x2f, 0xd2, 0x52, 0x75, 0x3a, 0x8a, 0x1c, 0xfa, 0x1e, 0xa1, 0x1c, 0x91,
      0x46, 0x79, 0x9a, 0xe5, 0x8a, 0xdd, 0xc2, 0x75, 0xed, 0x0d, 0xb8, 0x2b,
      0x4f, 0x8f, 0x95, 0xca, 0xce, 0x21, 0xa4, 0x7a, 0x0d, 0x14, 0x7f, 0x2d,
      0x98, 0xf0, 0x88, 0xc3, 0x6f, 0xad, 0xb5, 0x04, 0x24, 0x91, 0x41, 0x65,
      0xd3, 0xa5, 0x7e, 0xfb, 0x53, 0x1c, 0xcc, 0xd0, 0xf7, 0x7c, 0x91, 0x08,
      0x0e, 0xdd, 0xd4, 0x6c, 0x73, 0xaa, 0xa5, 0x7a, 0xd2, 0x24, 0xc9, 0x3b,
      0x6f, 0xda, 0x06, 0x8a, 0xdb, 0x2e, 0xa8, 0xe9, 0xe1, 0x3e, 0x08, 0xee,
      0xbe, 0x96, 0x65, 0x72, 0x68, 0x6f, 0xf7, 0x50, 0xe7, 0xa7, 0x18, 0xda,
      0xc2, 0x94, 0xda, 0xe3, 0xbc, 0xca, 0x03, 0xd8, 0xf7, 0x7a, 0xcc, 0x44,
      0xa1, 0x60, 0xa8, 0x7f, 0xdc, 0xef, 0x80, 0xf4, 0x62, 0xc6, 0x06, 0x4e,
      0xb6, 0xac, 0x77, 0x17, 0xb7, 0xb3, 0x3e, 0xf8, 0x6d, 0x8a, 0x61, 0x83,
      0x3a, 0xfd, 0xbb, 0x93, 0x5b, 0x1a, 0x33, 0xf8, 0xee, 0x7d, 0x9e, 0x5c,
      0xf8, 0xc9, 0xd5, 0x3e, 0x3d, 0x42, 0x9b, 0xe5, 0x0d, 0xec, 0xc9, 0x0f,
      0x6f, 0x03, 0xb0, 0x41, 0x85, 0xb9, 0xfe, 0xf9, 0xb1, 0xb4, 0xc3, 0xd9,
      0x13, 0x03, 0xfa, 0x0d, 0xe7, 0xd1, 0xb4, 0xc8, 0xf6, 0xb5, 0x11, 0x7a,
      0x92, 0x09, 0x21, 0x7b, 0xa9, 0x89, 0x4c, 0x19, 0x90, 0x0d, 0x96, 0x32,
      0x4f, 0x77, 0xfc, 0x7f, 0x8c, 0xa3, 0x39, 0x2a, 0x56, 0xe6, 0x5c, 0xd1,
      0x86, 0x0a, 0x72, 0xf4, 0xa3, 0x1b, 0xa5, 0x30, 0x04, 0x3c, 0x15, 0x20,
      0x4b, 0xe4, 0x2d, 0x1a, 0xf1, 0x44, 0x48, 0xfc, 0xda, 0xc1, 0x41, 0xdb,
      0x71, 0xfd, 0x92, 0x00, 0x53, 0xe4, 0x70, 0xd0, 0xba, 0xf6, 0xef, 0x17,
      0x72, 0xb8, 0xea, 0x6d, 0x41, 0x16, 0x4d, 0x1f, 0x59, 0x18, 0xbd, 0x1f,
      0xc5, 0x6b, 0x6a, 0x6c, 0x2e, 0xa6, 0x1a, 0x33, 0x74, 0x8b, 0xc5, 0x9f,
      0x16, 0x01, 0x77, 0x7e, 0x37, 0xe7, 0x63, 0xe1, 0xa3, 0x8c, 0x1f, 0x71,
      0xe9, 0x4f, 0xad, 0x15, 0x8b, 0xf3, 0xc9, 0xac, 0xdc, 0x19, 0xad, 0x92,
      0x18, 0x00, 0xf6, 0xa1, 0xd5, 0x97, 0xa3, 0x3d, 0x9e, 0x78, 0x02, 0xc3,
      0x8f, 0x75, 0xd8, 0xad, 0x22, 0xbf, 0xef, 0x19, 0x5d, 0x15, 0x34, 0x1a,
      0x7c, 0x9b, 0xaf, 0xd4, 0xf2, 0xf9, 0x5f, 0x72, 0x88, 0x9c, 0xe4, 0x58,
      0xda, 0x46, 0x8f, 0x79, 0x30, 0x2b, 0xd9, 0x3b, 0xbc, 0xab, 0x28, 0x77,
      0x75, 0x0e, 0x2c, 0x23, 0x47, 0x95, 0x14, 0xeb, 0xf0, 0x4a, 0x3e, 0x53,
      0x93, 0xa7, 0xf4, 0x82, 0x9c, 0x34, 0x8b, 0x80, 0x42, 0xb2, 0xa7, 0xb0,
      0x7c, 0x6c, 0xe1, 0x07, 0xf4, 0x34, 0x3e, 0xed, 0x33, 0x9c, 0xb3, 0xde,
      0xa5, 0x91, 0x61, 0x25, 0x8e, 0x8c, 0x54, 0x56, 0xbe, 0x1a, 0xac, 0x17,
      0xd2, 0x7a, 0xa4, 0x12, 0x54, 0x2a, 0x51, 0xd0, 0x0e, 0xd1, 0xc1, 0x44,
      0x50, 0x05, 0x39, 0xa7, 0xb6, 0x14, 0x45, 0xca, 0xf8, 0x5f, 0x06, 0x6b,
      0x5d, 0x5e, 0xc7, 0xe9, 0x27, 0x6f, 0x38, 0xe0, 0x31, 0xcf, 0xf8, 0xcc,
      0x2e, 0xb9, 0x4a, 0x10, 0x1b, 0xb4, 0x34, 0x4b, 0x90, 0xbb, 0xf2, 0xe0,
      0x3c, 0x79, 0x7f, 0x39, 0x59, 0x0c, 0x01, 0x4c, 0x0d, 0x2d, 0x71, 0xf1,
      0xbd, 0xda, 0x1a, 0x78, 0xcf, 0x26, 0x6f, 0xb5, 0xa9, 0x07, 0x20, 0xe6,
      0x8c, 0xd0, 0xad, 0xd4, 0xca, 0x24, 0x6c, 0xc5, 0x28, 0x1d, 0xfb, 0xcc,
      0xe7, 0x93, 0x72, 0x99, 0x61, 0x63, 0x60, 0x4c, 0x5c, 0xa9, 0xb6, 0x15,
      0x32, 0xa4, 0xbc, 0x1f, 0xf6, 0x63, 0x61, 0x2c, 0x26, 0xa7, 0x0e, 0x5f,
      0x1b, 0x25, 0xce, 0x3f, 0x64, 0xdf, 0x6d, 0xb0, 0x8f, 0xd2, 0xe9, 0x3b,
      0x35, 0xd0, 0x59, 0x81, 0x22, 0xf1, 0x65, 0x86, 0x15, 0x10, 0xe8, 0xa7,
      0xa1, 0x6f, 0xb4, 0x34, 0x1c, 0x79, 0xd5, 0x9e, 0x8d, 0xc8, 0xa5, 0xbb,
      0x82, 0x71, 0x81, 0x00, 0x34, 0x55, 0x6b, 0x96, 0x56, 0x13, 0x0e, 0xe7,
      0x39, 0xa2, 0x6f, 0xbe, 0x54, 0x2a, 0x13, 0x03, 0x13, 0xd2, 0x1d, 0x71,
      0x9a, 0xbe, 0x09, 0x00, 0xe1, 0x8d, 0x59, 0xb5, 0x44, 0x02,
  };
  EXPECT_EQ(Bytes(ciphertext), Bytes(kExpectedCiphertext));

  static const uint8_t kExpectedSharedKey[HRSS_KEY_BYTES] = {
      0x57, 0xf2, 0x77, 0xb2, 0xf3, 0x7f, 0xd0, 0x71, 0xb6, 0x7e, 0x64,
      0x0f, 0x85, 0x1f, 0x6d, 0x3b, 0xd1, 0x7a, 0x6e, 0x01, 0x04, 0xde,
      0x0f, 0x9e, 0x03, 0x95, 0x55, 0x60, 0xce, 0xda, 0x32, 0x71,
  };
  EXPECT_EQ(Bytes(shared_key), Bytes(kExpectedSharedKey));

  ASSERT_TRUE(HRSS_decap(shared_key, &priv, ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(Bytes(shared_key, sizeof(shared_key)),
            Bytes(kExpectedSharedKey, sizeof(kExpectedSharedKey)));

  // Corrupt the ciphertext and ensure that the failure key is constant.
  ciphertext[50] ^= 4;
  ASSERT_TRUE(HRSS_decap(shared_key, &priv, ciphertext, sizeof(ciphertext)));

  static const uint8_t kExpectedFailureKey[HRSS_KEY_BYTES] = {
      0x13, 0xf7, 0xed, 0x51, 0x00, 0xbc, 0xca, 0x29, 0xdf, 0xb0, 0xd0,
      0x5e, 0xa1, 0x9d, 0x15, 0xb2, 0xf6, 0x23, 0x94, 0xfd, 0x93, 0x74,
      0x14, 0x46, 0x85, 0x61, 0x8b, 0x87, 0x30, 0xd3, 0x8d, 0xad,
  };
  EXPECT_EQ(Bytes(shared_key), Bytes(kExpectedFailureKey));
}

#if defined(POLY_RQ_MUL_ASM) && defined(SUPPORTS_ABI_TEST)
TEST(HRSS, ABI) {
  const bool has_avx2 = (OPENSSL_ia32cap_P[2] & (1 << 5)) != 0;
  if (!has_avx2) {
    fprintf(stderr, "Skipping ABI test due to lack of AVX2 support.\n");
    return;
  }

  alignas(16) uint16_t r[N + 3];
  alignas(16) uint16_t a[N + 3] = {0};
  alignas(16) uint16_t b[N + 3] = {0};
  alignas(32) uint8_t scratch[POLY_MUL_RQ_SCRATCH_SPACE];
  CHECK_ABI(poly_Rq_mul, r, a, b, scratch);
}
#endif  // POLY_RQ_MUL_ASM && SUPPORTS_ABI_TEST
