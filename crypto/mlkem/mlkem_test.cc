/* Copyright (c) 2023, Google Inc.
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

#include <vector>

#include <string.h>

#include <gtest/gtest.h>

#include <openssl/bytestring.h>
#include <openssl/ctrdrbg.h>
#include <openssl/mlkem.h>

#include "../keccak/internal.h"
#include "../test/file_test.h"
#include "../test/test_util.h"
#include "./internal.h"


namespace {

template <typename T>
std::vector<uint8_t> Marshal(int (*marshal_func)(CBB *, const T *),
                             const T *t) {
  bssl::ScopedCBB cbb;
  uint8_t *encoded;
  size_t encoded_len;
  if (!CBB_init(cbb.get(), 1) ||      //
      !marshal_func(cbb.get(), t) ||  //
      !CBB_finish(cbb.get(), &encoded, &encoded_len)) {
    abort();
  }

  std::vector<uint8_t> ret(encoded, encoded + encoded_len);
  OPENSSL_free(encoded);
  return ret;
}

template <typename PUBLIC_KEY, size_t PUBLIC_KEY_BYTES, typename PRIVATE_KEY,
          size_t PRIVATE_KEY_BYTES,
          void (*GENERATE)(uint8_t *, uint8_t *, PRIVATE_KEY *),
          void (*FROM_SEED)(PRIVATE_KEY *, const uint8_t *),
          void PUBLIC_FROM_PRIVATE(PUBLIC_KEY *, const PRIVATE_KEY *),
          int (*PARSE_PUBLIC)(PUBLIC_KEY *, CBS *),
          int (*MARSHAL_PUBLIC)(CBB *, const PUBLIC_KEY *),
          int (*PARSE_PRIVATE)(PRIVATE_KEY *, CBS *),
          int (*MARSHAL_PRIVATE)(CBB *, const PRIVATE_KEY *),
          size_t CIPHERTEXT_BYTES,
          void (*ENCAP)(uint8_t *, uint8_t *, const PUBLIC_KEY *),
          void (*DECAP)(uint8_t *, const uint8_t *, const PRIVATE_KEY *)>
void BasicTest() {
  // This function makes several ML-KEM keys, which runs up against stack
  // limits. Heap-allocate them instead.

  uint8_t encoded_public_key[PUBLIC_KEY_BYTES];
  uint8_t seed[MLKEM_SEED_BYTES];
  auto priv = std::make_unique<PRIVATE_KEY>();
  GENERATE(encoded_public_key, seed, priv.get());

  {
    auto priv2 = std::make_unique<PRIVATE_KEY>();
    FROM_SEED(priv2.get(), seed);
    EXPECT_EQ(Bytes(Marshal(MARSHAL_PRIVATE, priv.get())),
              Bytes(Marshal(MARSHAL_PRIVATE, priv2.get())));
  }

  uint8_t first_two_bytes[2];
  OPENSSL_memcpy(first_two_bytes, encoded_public_key, sizeof(first_two_bytes));
  OPENSSL_memset(encoded_public_key, 0xff, sizeof(first_two_bytes));
  CBS encoded_public_key_cbs;
  CBS_init(&encoded_public_key_cbs, encoded_public_key,
           sizeof(encoded_public_key));
  auto pub = std::make_unique<PUBLIC_KEY>();
  // Parsing should fail because the first coefficient is >= kPrime;
  ASSERT_FALSE(PARSE_PUBLIC(pub.get(), &encoded_public_key_cbs));

  OPENSSL_memcpy(encoded_public_key, first_two_bytes, sizeof(first_two_bytes));
  CBS_init(&encoded_public_key_cbs, encoded_public_key,
           sizeof(encoded_public_key));
  ASSERT_TRUE(PARSE_PUBLIC(pub.get(), &encoded_public_key_cbs));
  EXPECT_EQ(CBS_len(&encoded_public_key_cbs), 0u);

  EXPECT_EQ(Bytes(encoded_public_key),
            Bytes(Marshal(MARSHAL_PUBLIC, pub.get())));

  auto pub2 = std::make_unique<PUBLIC_KEY>();
  PUBLIC_FROM_PRIVATE(pub2.get(), priv.get());
  EXPECT_EQ(Bytes(encoded_public_key),
            Bytes(Marshal(MARSHAL_PUBLIC, pub2.get())));

  std::vector<uint8_t> encoded_private_key(
      Marshal(MARSHAL_PRIVATE, priv.get()));
  EXPECT_EQ(encoded_private_key.size(), size_t{PRIVATE_KEY_BYTES});

  OPENSSL_memcpy(first_two_bytes, encoded_private_key.data(),
                 sizeof(first_two_bytes));
  OPENSSL_memset(encoded_private_key.data(), 0xff, sizeof(first_two_bytes));
  CBS cbs;
  CBS_init(&cbs, encoded_private_key.data(), encoded_private_key.size());
  auto priv2 = std::make_unique<PRIVATE_KEY>();
  // Parsing should fail because the first coefficient is >= kPrime.
  ASSERT_FALSE(PARSE_PRIVATE(priv2.get(), &cbs));

  OPENSSL_memcpy(encoded_private_key.data(), first_two_bytes,
                 sizeof(first_two_bytes));
  CBS_init(&cbs, encoded_private_key.data(), encoded_private_key.size());
  ASSERT_TRUE(PARSE_PRIVATE(priv2.get(), &cbs));
  EXPECT_EQ(Bytes(encoded_private_key),
            Bytes(Marshal(MARSHAL_PRIVATE, priv2.get())));

  uint8_t ciphertext[CIPHERTEXT_BYTES];
  uint8_t shared_secret1[MLKEM_SHARED_SECRET_BYTES];
  uint8_t shared_secret2[MLKEM_SHARED_SECRET_BYTES];
  ENCAP(ciphertext, shared_secret1, pub.get());
  DECAP(shared_secret2, ciphertext, priv.get());
  EXPECT_EQ(Bytes(shared_secret1), Bytes(shared_secret2));
  DECAP(shared_secret2, ciphertext, priv2.get());
  EXPECT_EQ(Bytes(shared_secret1), Bytes(shared_secret2));
}

TEST(MLKEMTest, Basic768) {
  BasicTest<MLKEM_public_key, MLKEM_PUBLIC_KEY_BYTES, MLKEM_private_key,
            MLKEM_PRIVATE_KEY_BYTES, MLKEM_generate_key,
            MLKEM_private_key_from_seed, MLKEM_public_from_private,
            MLKEM_parse_public_key, MLKEM_marshal_public_key,
            MLKEM_parse_private_key, MLKEM_marshal_private_key,
            MLKEM_CIPHERTEXT_BYTES, MLKEM_encap, MLKEM_decap>();
}

TEST(MLKEMTest, Basic1024) {
  BasicTest<MLKEM1024_public_key, MLKEM1024_PUBLIC_KEY_BYTES,
            MLKEM1024_private_key, MLKEM1024_PRIVATE_KEY_BYTES,
            MLKEM1024_generate_key, MLKEM1024_private_key_from_seed,
            MLKEM1024_public_from_private, MLKEM1024_parse_public_key,
            MLKEM1024_marshal_public_key, MLKEM1024_parse_private_key,
            MLKEM1024_marshal_private_key, MLKEM1024_CIPHERTEXT_BYTES,
            MLKEM1024_encap, MLKEM1024_decap>();
}

template <typename PUBLIC_KEY, size_t PUBLIC_KEY_BYTES,
          int (*PARSE_PUBLIC)(PUBLIC_KEY *, CBS *), size_t CIPHERTEXT_BYTES,
          void (*ENCAP)(uint8_t *, uint8_t *, const PUBLIC_KEY *,
                        const uint8_t *)>
void MLKEMEncapFileTest(FileTest *t) {
  std::vector<uint8_t> pub_key_bytes, entropy, expected_ciphertext,
      expected_shared_secret;
  ASSERT_TRUE(t->GetBytes(&pub_key_bytes, "ek"));
  ASSERT_TRUE(t->GetBytes(&entropy, "m"));
  ASSERT_TRUE(t->GetBytes(&expected_ciphertext, "c"));
  ASSERT_TRUE(t->GetBytes(&expected_shared_secret, "K"));

  PUBLIC_KEY pub_key;
  CBS pub_key_cbs;
  CBS_init(&pub_key_cbs, pub_key_bytes.data(), pub_key_bytes.size());
  ASSERT_TRUE(PARSE_PUBLIC(&pub_key, &pub_key_cbs));

  uint8_t ciphertext[CIPHERTEXT_BYTES];
  uint8_t shared_secret[MLKEM_SHARED_SECRET_BYTES];
  ENCAP(ciphertext, shared_secret, &pub_key, entropy.data());

  ASSERT_EQ(Bytes(expected_ciphertext), Bytes(ciphertext));
  ASSERT_EQ(Bytes(expected_shared_secret), Bytes(shared_secret));
}

TEST(MLKEMTest, Encap768TestVectors) {
  FileTestGTest(
      "crypto/mlkem/mlkem768_encap_tests.txt",
      MLKEMEncapFileTest<MLKEM_public_key, MLKEM_PUBLIC_KEY_BYTES,
                         MLKEM_parse_public_key, MLKEM_CIPHERTEXT_BYTES,
                         MLKEM_encap_external_entropy>);
}

TEST(MLKEMTest, Encap1024TestVectors) {
  FileTestGTest(
      "crypto/mlkem/mlkem1024_encap_tests.txt",
      MLKEMEncapFileTest<MLKEM1024_public_key, MLKEM1024_PUBLIC_KEY_BYTES,
                         MLKEM1024_parse_public_key, MLKEM1024_CIPHERTEXT_BYTES,
                         MLKEM1024_encap_external_entropy>);
}

template <typename PRIVATE_KEY, size_t PRIVATE_KEY_BYTES,
          int (*PARSE_PRIVATE)(PRIVATE_KEY *, CBS *), size_t CIPHERTEXT_BYTES,
          void (*DECAP)(uint8_t *, const uint8_t *, const PRIVATE_KEY *)>
void MLKEMDecapFileTest(FileTest *t) {
  std::vector<uint8_t> priv_key_bytes, ciphertext, expected_shared_secret;
  ASSERT_TRUE(t->GetBytes(&priv_key_bytes, "dk"));
  ASSERT_TRUE(t->GetBytes(&ciphertext, "c"));
  ASSERT_TRUE(t->GetBytes(&expected_shared_secret, "KPrime"));

  PRIVATE_KEY priv_key;
  CBS priv_key_cbs;
  CBS_init(&priv_key_cbs, priv_key_bytes.data(), priv_key_bytes.size());
  ASSERT_TRUE(PARSE_PRIVATE(&priv_key, &priv_key_cbs));

  uint8_t shared_secret[MLKEM_SHARED_SECRET_BYTES];
  DECAP(shared_secret, ciphertext.data(), &priv_key);

  ASSERT_EQ(Bytes(expected_shared_secret), Bytes(shared_secret));
}

TEST(MLKEMTest, Decap768TestVectors) {
  FileTestGTest("crypto/mlkem/mlkem768_decap_tests.txt",
                MLKEMDecapFileTest<MLKEM_private_key, MLKEM_PRIVATE_KEY_BYTES,
                                   MLKEM_parse_private_key,
                                   MLKEM_CIPHERTEXT_BYTES, MLKEM_decap>);
}

TEST(MLKEMTest, Decap1024TestVectors) {
  FileTestGTest(
      "crypto/mlkem/mlkem1024_decap_tests.txt",
      MLKEMDecapFileTest<MLKEM1024_private_key, MLKEM1024_PRIVATE_KEY_BYTES,
                         MLKEM1024_parse_private_key,
                         MLKEM1024_CIPHERTEXT_BYTES, MLKEM1024_decap>);
}

template <
    typename PUBLIC_KEY, size_t PUBLIC_KEY_BYTES, typename PRIVATE_KEY,
    size_t PRIVATE_KEY_BYTES,
    void (*GENERATE)(uint8_t *, PRIVATE_KEY *, const uint8_t *),
    void (*TO_PUBLIC)(PUBLIC_KEY *, const PRIVATE_KEY *),
    int (*MARSHAL_PRIVATE)(CBB *, const PRIVATE_KEY *), size_t CIPHERTEXT_BYTES,
    void (*ENCAP)(uint8_t *, uint8_t *, const PUBLIC_KEY *, const uint8_t *),
    void (*DECAP)(uint8_t *, const uint8_t *, const PRIVATE_KEY *)>
void IteratedTest(uint8_t out[32]) {
  BORINGSSL_keccak_st generate_st;
  BORINGSSL_keccak_init(&generate_st, boringssl_shake128);
  BORINGSSL_keccak_st results_st;
  BORINGSSL_keccak_init(&results_st, boringssl_shake128);

  auto priv = std::make_unique<PRIVATE_KEY>();
  auto pub = std::make_unique<PUBLIC_KEY>();
  for (int i = 0; i < 10000; i++) {
    uint8_t generate_entropy[MLKEM_SEED_BYTES];
    BORINGSSL_keccak_squeeze(&generate_st, generate_entropy,
                             sizeof(generate_entropy));
    uint8_t encoded_pub[PUBLIC_KEY_BYTES];
    GENERATE(encoded_pub, priv.get(), generate_entropy);
    TO_PUBLIC(pub.get(), priv.get());

    BORINGSSL_keccak_absorb(&results_st, encoded_pub, sizeof(encoded_pub));
    const std::vector<uint8_t> encoded_priv(
        Marshal(MARSHAL_PRIVATE, priv.get()));
    BORINGSSL_keccak_absorb(&results_st, encoded_priv.data(),
                            encoded_priv.size());

    uint8_t encap_entropy[MLKEM_ENCAP_ENTROPY];
    BORINGSSL_keccak_squeeze(&generate_st, encap_entropy,
                             sizeof(encap_entropy));
    uint8_t ciphertext[CIPHERTEXT_BYTES];
    uint8_t shared_secret[MLKEM_SHARED_SECRET_BYTES];
    ENCAP(ciphertext, shared_secret, pub.get(), encap_entropy);

    BORINGSSL_keccak_absorb(&results_st, ciphertext, sizeof(ciphertext));
    BORINGSSL_keccak_absorb(&results_st, shared_secret, sizeof(shared_secret));

    uint8_t invalid_ciphertext[CIPHERTEXT_BYTES];
    BORINGSSL_keccak_squeeze(&generate_st, invalid_ciphertext,
                             sizeof(invalid_ciphertext));
    DECAP(shared_secret, invalid_ciphertext, priv.get());

    BORINGSSL_keccak_absorb(&results_st, shared_secret, sizeof(shared_secret));
  }

  BORINGSSL_keccak_squeeze(&results_st, out, 32);
}

TEST(MLKEMTest, Iterate768) {
  uint8_t result[32];
  IteratedTest<MLKEM_public_key, MLKEM_PUBLIC_KEY_BYTES, MLKEM_private_key,
               MLKEM_PRIVATE_KEY_BYTES, MLKEM_generate_key_external_entropy,
               MLKEM_public_from_private, MLKEM_marshal_private_key,
               MLKEM_CIPHERTEXT_BYTES, MLKEM_encap_external_entropy,
               MLKEM_decap>(result);

  const uint8_t kExpected[32] = {
      0xf9, 0x59, 0xd1, 0x8d, 0x3d, 0x11, 0x80, 0x12, 0x14, 0x33, 0xbf,
      0x0e, 0x05, 0xf1, 0x1e, 0x79, 0x08, 0xcf, 0x9d, 0x03, 0xed, 0xc1,
      0x50, 0xb2, 0xb0, 0x7c, 0xb9, 0x0b, 0xef, 0x5b, 0xc1, 0xc1};
  EXPECT_EQ(Bytes(result), Bytes(kExpected));
}


TEST(MLKEMTest, Iterate1024) {
  uint8_t result[32];
  IteratedTest<MLKEM1024_public_key, MLKEM1024_PUBLIC_KEY_BYTES,
               MLKEM1024_private_key, MLKEM1024_PRIVATE_KEY_BYTES,
               MLKEM1024_generate_key_external_entropy,
               MLKEM1024_public_from_private, MLKEM1024_marshal_private_key,
               MLKEM1024_CIPHERTEXT_BYTES, MLKEM1024_encap_external_entropy,
               MLKEM1024_decap>(result);

  const uint8_t kExpected[32] = {
      0xe3, 0xbf, 0x82, 0xb0, 0x13, 0x30, 0x7b, 0x2e, 0x9d, 0x47, 0xdd,
      0xe7, 0x91, 0xff, 0x6d, 0xfc, 0x82, 0xe6, 0x94, 0xe6, 0x38, 0x24,
      0x04, 0xab, 0xdb, 0x94, 0x8b, 0x90, 0x8b, 0x75, 0xba, 0xd5};
  EXPECT_EQ(Bytes(result), Bytes(kExpected));
}
}  // namespace
