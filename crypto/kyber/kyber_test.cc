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
#include <openssl/kyber.h>

#include "../test/file_test.h"
#include "../test/test_util.h"
#include "./internal.h"


static void KeccakFileTest(FileTest *t) {
  std::vector<uint8_t> input, sha3_256_expected, sha3_512_expected,
      shake128_expected, shake256_expected;
  ASSERT_TRUE(t->GetBytes(&input, "Input"));
  ASSERT_TRUE(t->GetBytes(&sha3_256_expected, "SHA3-256"));
  ASSERT_TRUE(t->GetBytes(&sha3_512_expected, "SHA3-512"));
  ASSERT_TRUE(t->GetBytes(&shake128_expected, "SHAKE-128"));
  ASSERT_TRUE(t->GetBytes(&shake256_expected, "SHAKE-256"));

  uint8_t sha3_256_digest[32];
  BORINGSSL_keccak(sha3_256_digest, sizeof(sha3_256_digest), input.data(),
                   input.size(), boringssl_sha3_256);
  uint8_t sha3_512_digest[64];
  BORINGSSL_keccak(sha3_512_digest, sizeof(sha3_512_digest), input.data(),
                   input.size(), boringssl_sha3_512);
  uint8_t shake128_output[512];
  BORINGSSL_keccak(shake128_output, sizeof(shake128_output), input.data(),
                   input.size(), boringssl_shake128);
  uint8_t shake256_output[512];
  BORINGSSL_keccak(shake256_output, sizeof(shake256_output), input.data(),
                   input.size(), boringssl_shake256);

  EXPECT_EQ(Bytes(sha3_256_expected), Bytes(sha3_256_digest));
  EXPECT_EQ(Bytes(sha3_512_expected), Bytes(sha3_512_digest));
  EXPECT_EQ(Bytes(shake128_expected), Bytes(shake128_output));
  EXPECT_EQ(Bytes(shake256_expected), Bytes(shake256_output));

  struct BORINGSSL_keccak_st ctx;

  BORINGSSL_keccak_init(&ctx, boringssl_shake128);
  BORINGSSL_keccak_absorb(&ctx, input.data(), input.size());
  for (size_t i = 0; i < sizeof(shake128_output); i++) {
    BORINGSSL_keccak_squeeze(&ctx, &shake128_output[i], 1);
  }
  EXPECT_EQ(Bytes(shake128_expected), Bytes(shake128_output));

  BORINGSSL_keccak_init(&ctx, boringssl_shake256);
  BORINGSSL_keccak_absorb(&ctx, input.data(), input.size());
  for (size_t i = 0; i < sizeof(shake256_output); i++) {
    BORINGSSL_keccak_squeeze(&ctx, &shake256_output[i], 1);
  }
  EXPECT_EQ(Bytes(shake256_expected), Bytes(shake256_output));
}

TEST(KyberTest, KeccakTestVectors) {
  FileTestGTest("crypto/kyber/keccak_tests.txt", KeccakFileTest);
}

static void cSHAKEFileTest(FileTest *t) {
  std::vector<uint8_t> input, customization, cshake128_expected,
      cshake256_expected;
  ASSERT_TRUE(t->GetBytes(&input, "Input"));
  ASSERT_TRUE(t->GetBytes(&customization, "Customization"));
  ASSERT_TRUE(t->GetBytes(&cshake128_expected, "cSHAKE-128"));
  ASSERT_TRUE(t->GetBytes(&cshake256_expected, "cSHAKE-256"));

  {
    struct BORINGSSL_keccak_st ctx;
    BORINGSSL_keccak_init_with_customization(
        &ctx, boringssl_cshake128, customization.data(), customization.size());
    BORINGSSL_keccak_absorb(&ctx, input.data(), input.size());
    std::vector<uint8_t> output(cshake128_expected.size());
    BORINGSSL_keccak_squeeze(&ctx, output.data(), output.size());
    EXPECT_EQ(Bytes(cshake128_expected), Bytes(output));
  }

  {
    struct BORINGSSL_keccak_st ctx;
    BORINGSSL_keccak_init_with_customization(
        &ctx, boringssl_cshake256, customization.data(), customization.size());
    BORINGSSL_keccak_absorb(&ctx, input.data(), input.size());
    std::vector<uint8_t> output(cshake256_expected.size());
    BORINGSSL_keccak_squeeze(&ctx, output.data(), output.size());
    EXPECT_EQ(Bytes(cshake256_expected), Bytes(output));
  }
}

TEST(KyberTest, cSHAKETestVectors) {
  FileTestGTest("crypto/kyber/cshake_tests.txt", cSHAKEFileTest);
}

TEST(KyberTest, cSHAKEFallback) {
  // cSHAKE is defined to be equal to SHAKE (via special exception) when the
  // customization string is empty.

  auto check = [](boringssl_keccak_customization_config_t cshake_config,
                  boringssl_keccak_config_t shake_config) {
    struct BORINGSSL_keccak_st ctx;
    BORINGSSL_keccak_init_with_customization(&ctx, cshake_config, nullptr, 0);
    uint8_t output[32];
    BORINGSSL_keccak_squeeze(&ctx, output, sizeof(output));

    uint8_t expected_output[32];
    BORINGSSL_keccak(expected_output, sizeof(expected_output), nullptr, 0,
                     shake_config);
    EXPECT_EQ(Bytes(output), Bytes(expected_output));
  };

  check(boringssl_cshake128, boringssl_shake128);
  check(boringssl_cshake256, boringssl_shake256);
}

TEST(KyberTest, TurboSHAKE) {
  // There aren't good test vectors for TurboSHAKE, but the bulk of the
  // machinery is already tested so this test just confirms that the digest of
  // the empty string matches what https://github.com/cloudflare/circl things
  // the answer is.

  {
    static const uint8_t kExpected[] = {
        0x1e, 0x41, 0x5f, 0x1c, 0x59, 0x83, 0xaf, 0xf2,
        0x16, 0x92, 0x17, 0x27, 0x7d, 0x17, 0xbb, 0x53,
    };
    uint8_t calculated[sizeof(kExpected)];
    BORINGSSL_keccak(calculated, sizeof(calculated), nullptr, 0,
                     boringssl_turboshake128);
    EXPECT_EQ(Bytes(kExpected), Bytes(calculated));
  }

  {
    static const uint8_t kExpected[] = {
        0x36, 0x7a, 0x32, 0x9d, 0xaf, 0xea, 0x87, 0x1c,
        0x78, 0x02, 0xec, 0x67, 0xf9, 0x05, 0xae, 0x13,
    };
    uint8_t calculated[sizeof(kExpected)];
    BORINGSSL_keccak(calculated, sizeof(calculated), nullptr, 0,
                     boringssl_turboshake256);
    EXPECT_EQ(Bytes(kExpected), Bytes(calculated));
  }
}

TEST(KyberTest, InputSizes) {
  // Check that all sizes of writes work correctly.

  uint8_t data[512];
  BORINGSSL_keccak(data, sizeof(data), nullptr, 0, boringssl_shake128);
  uint8_t expected_digest[32];
  BORINGSSL_keccak(expected_digest, sizeof(expected_digest), data, sizeof(data),
                   boringssl_sha3_256);

  for (size_t stride = 1; stride < sizeof(data); stride++) {
    SCOPED_TRACE(stride);

    struct BORINGSSL_keccak_st ctx;
    BORINGSSL_keccak_init(&ctx, boringssl_sha3_256);

    size_t done = 0;
    while (done < sizeof(data)) {
      size_t todo = sizeof(data) - done;
      if (todo > stride) {
        todo = stride;
      }
      BORINGSSL_keccak_absorb(&ctx, data + done, todo);
      done += todo;
    }

    uint8_t digest[sizeof(expected_digest)];
    BORINGSSL_keccak_squeeze(&ctx, digest, sizeof(digest));

    EXPECT_EQ(Bytes(expected_digest), Bytes(digest));
  }
}

template <typename T>
static std::vector<uint8_t> Marshal(int (*marshal_func)(CBB *, const T *),
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

TEST(KyberTest, Basic) {
  uint8_t encoded_public_key[KYBER_PUBLIC_KEY_BYTES];
  KYBER_private_key priv;
  KYBER_generate_key(encoded_public_key, &priv);

  uint8_t first_two_bytes[2];
  OPENSSL_memcpy(first_two_bytes, encoded_public_key, sizeof(first_two_bytes));
  OPENSSL_memset(encoded_public_key, 0xff, sizeof(first_two_bytes));
  CBS encoded_public_key_cbs;
  CBS_init(&encoded_public_key_cbs, encoded_public_key,
           sizeof(encoded_public_key));
  KYBER_public_key pub;
  // Parsing should fail because the first coefficient is >= kPrime;
  ASSERT_FALSE(KYBER_parse_public_key(&pub, &encoded_public_key_cbs));

  OPENSSL_memcpy(encoded_public_key, first_two_bytes, sizeof(first_two_bytes));
  CBS_init(&encoded_public_key_cbs, encoded_public_key,
           sizeof(encoded_public_key));
  ASSERT_TRUE(KYBER_parse_public_key(&pub, &encoded_public_key_cbs));
  EXPECT_EQ(CBS_len(&encoded_public_key_cbs), 0u);

  EXPECT_EQ(Bytes(encoded_public_key),
            Bytes(Marshal(KYBER_marshal_public_key, &pub)));

  KYBER_public_key pub2;
  KYBER_public_from_private(&pub2, &priv);
  EXPECT_EQ(Bytes(encoded_public_key),
            Bytes(Marshal(KYBER_marshal_public_key, &pub2)));

  std::vector<uint8_t> encoded_private_key(
      Marshal(KYBER_marshal_private_key, &priv));
  EXPECT_EQ(encoded_private_key.size(), size_t{KYBER_PRIVATE_KEY_BYTES});

  OPENSSL_memcpy(first_two_bytes, encoded_private_key.data(),
                 sizeof(first_two_bytes));
  OPENSSL_memset(encoded_private_key.data(), 0xff, sizeof(first_two_bytes));
  CBS cbs;
  CBS_init(&cbs, encoded_private_key.data(), encoded_private_key.size());
  KYBER_private_key priv2;
  // Parsing should fail because the first coefficient is >= kPrime.
  ASSERT_FALSE(KYBER_parse_private_key(&priv2, &cbs));

  OPENSSL_memcpy(encoded_private_key.data(), first_two_bytes,
                 sizeof(first_two_bytes));
  CBS_init(&cbs, encoded_private_key.data(), encoded_private_key.size());
  ASSERT_TRUE(KYBER_parse_private_key(&priv2, &cbs));
  EXPECT_EQ(Bytes(encoded_private_key),
            Bytes(Marshal(KYBER_marshal_private_key, &priv2)));

  uint8_t ciphertext[KYBER_CIPHERTEXT_BYTES];
  uint8_t shared_secret1[64];
  uint8_t shared_secret2[sizeof(shared_secret1)];
  KYBER_encap(ciphertext, shared_secret1, sizeof(shared_secret1), &pub);
  KYBER_decap(shared_secret2, sizeof(shared_secret2), ciphertext, &priv);
  EXPECT_EQ(Bytes(shared_secret1), Bytes(shared_secret2));
  KYBER_decap(shared_secret2, sizeof(shared_secret2), ciphertext, &priv2);
  EXPECT_EQ(Bytes(shared_secret1), Bytes(shared_secret2));
}

static void KyberFileTest(FileTest *t) {
  std::vector<uint8_t> seed, public_key_expected, private_key_expected,
      ciphertext_expected, shared_secret_expected, given_generate_entropy,
      given_encap_entropy_pre_hash;
  t->IgnoreAttribute("count");
  ASSERT_TRUE(t->GetBytes(&seed, "seed"));
  ASSERT_TRUE(t->GetBytes(&public_key_expected, "pk"));
  ASSERT_TRUE(t->GetBytes(&private_key_expected, "sk"));
  ASSERT_TRUE(t->GetBytes(&ciphertext_expected, "ct"));
  ASSERT_TRUE(t->GetBytes(&shared_secret_expected, "ss"));
  ASSERT_TRUE(t->GetBytes(&given_generate_entropy, "generateEntropy"));
  ASSERT_TRUE(
      t->GetBytes(&given_encap_entropy_pre_hash, "encapEntropyPreHash"));

  KYBER_private_key priv;
  uint8_t encoded_private_key[KYBER_PRIVATE_KEY_BYTES];
  KYBER_public_key pub;
  uint8_t encoded_public_key[KYBER_PUBLIC_KEY_BYTES];
  uint8_t ciphertext[KYBER_CIPHERTEXT_BYTES];
  uint8_t gen_key_entropy[KYBER_GENERATE_KEY_ENTROPY];
  uint8_t encap_entropy[KYBER_ENCAP_ENTROPY];
  uint8_t encapsulated_key[32];
  uint8_t decapsulated_key[32];
  // The test vectors provide a CTR-DRBG seed which is used to generate the
  // input entropy.
  ASSERT_EQ(seed.size(), size_t{CTR_DRBG_ENTROPY_LEN});
  {
    bssl::UniquePtr<CTR_DRBG_STATE> state(
        CTR_DRBG_new(seed.data(), nullptr, 0));
    ASSERT_TRUE(state);
    ASSERT_TRUE(
        CTR_DRBG_generate(state.get(), gen_key_entropy, 32, nullptr, 0));
    ASSERT_TRUE(
        CTR_DRBG_generate(state.get(), gen_key_entropy + 32, 32, nullptr, 0));
    ASSERT_TRUE(CTR_DRBG_generate(state.get(), encap_entropy,
                                  KYBER_ENCAP_ENTROPY, nullptr, 0));
  }

  EXPECT_EQ(Bytes(gen_key_entropy), Bytes(given_generate_entropy));
  EXPECT_EQ(Bytes(encap_entropy), Bytes(given_encap_entropy_pre_hash));

  BORINGSSL_keccak(encap_entropy, sizeof(encap_entropy), encap_entropy,
                   sizeof(encap_entropy), boringssl_sha3_256);

  KYBER_generate_key_external_entropy(encoded_public_key, &priv,
                                      gen_key_entropy);
  CBB cbb;
  CBB_init_fixed(&cbb, encoded_private_key, sizeof(encoded_private_key));
  ASSERT_TRUE(KYBER_marshal_private_key(&cbb, &priv));
  CBS encoded_public_key_cbs;
  CBS_init(&encoded_public_key_cbs, encoded_public_key,
           sizeof(encoded_public_key));
  ASSERT_TRUE(KYBER_parse_public_key(&pub, &encoded_public_key_cbs));
  KYBER_encap_external_entropy(ciphertext, encapsulated_key,
                               sizeof(encapsulated_key), &pub, encap_entropy);
  KYBER_decap(decapsulated_key, sizeof(decapsulated_key), ciphertext, &priv);

  EXPECT_EQ(Bytes(encapsulated_key), Bytes(decapsulated_key));
  EXPECT_EQ(Bytes(private_key_expected), Bytes(encoded_private_key));
  EXPECT_EQ(Bytes(public_key_expected), Bytes(encoded_public_key));
  EXPECT_EQ(Bytes(ciphertext_expected), Bytes(ciphertext));
  EXPECT_EQ(Bytes(shared_secret_expected), Bytes(encapsulated_key));

  uint8_t corrupted_ciphertext[KYBER_CIPHERTEXT_BYTES];
  OPENSSL_memcpy(corrupted_ciphertext, ciphertext, KYBER_CIPHERTEXT_BYTES);
  corrupted_ciphertext[3] ^= 0x40;
  uint8_t corrupted_decapsulated_key[32];
  KYBER_decap(corrupted_decapsulated_key, sizeof(corrupted_decapsulated_key),
              corrupted_ciphertext, &priv);
  // It would be nice to have actual test vectors for the failure case, but the
  // NIST submission currently does not include those, so we are just testing
  // for inequality.
  EXPECT_NE(Bytes(encapsulated_key), Bytes(corrupted_decapsulated_key));
}

TEST(KyberTest, TestVectors) {
  FileTestGTest("crypto/kyber/kyber_tests.txt", KyberFileTest);
}
