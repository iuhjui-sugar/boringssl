/* Copyright (c) 2024, Google LLC
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

#include <openssl/mldsa.h>

#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <openssl/bytestring.h>
#include <openssl/ctrdrbg.h>
#include <openssl/span.h>

#include "../internal.h"
#include "../test/file_test.h"
#include "../test/test_util.h"
#include "./internal.h"


namespace {

std::vector<uint8_t> CBBToVector(std::function<int(CBB *)> callback) {
  CBB cbb;
  CBB_init(&cbb, 128);

  if (!callback(&cbb)) {
    abort();
  }

  uint8_t *data = nullptr;
  size_t len = 0;
  if (!CBB_finish(&cbb, &data, &len)) {
    abort();
  }

  std::vector<uint8_t> result;
  result.assign(data, data + len);
  OPENSSL_free(data);
  return result;
}

// This test is very slow, so it is disabled by default.
TEST(MLDSATest, DISABLED_BitFlips) {
  std::vector<uint8_t> encoded_public_key(MLDSA_PUBLIC_KEY_BYTES);
  auto priv = std::make_unique<MLDSA_private_key>();
  EXPECT_TRUE(
      MLDSA_generate_key(encoded_public_key.data(), nullptr, priv.get()));

  std::vector<uint8_t> encoded_signature(MLDSA_SIGNATURE_BYTES);
  static const uint8_t kMessage[] = {'H', 'e', 'l', 'l', 'o', ' ',
                                     'w', 'o', 'r', 'l', 'd'};
  EXPECT_TRUE(MLDSA_sign(encoded_signature.data(), priv.get(), kMessage,
                         sizeof(kMessage), nullptr, 0));

  auto pub = std::make_unique<MLDSA_public_key>();
  CBS cbs = bssl::MakeConstSpan(encoded_public_key);
  ASSERT_TRUE(MLDSA_parse_public_key(pub.get(), &cbs));

  EXPECT_EQ(MLDSA_verify(pub.get(), encoded_signature.data(),
                         encoded_signature.size(), kMessage, sizeof(kMessage),
                         nullptr, 0),
            1);

  for (size_t i = 0; i < MLDSA_SIGNATURE_BYTES; i++) {
    for (int j = 0; j < 8; j++) {
      encoded_signature[i] ^= 1 << j;
      EXPECT_EQ(MLDSA_verify(pub.get(), encoded_signature.data(),
                             encoded_signature.size(), kMessage,
                             sizeof(kMessage), nullptr, 0),
                0)
          << "Bit flip in signature at byte " << i << " bit " << j
          << " didn't cause a verification failure";
      encoded_signature[i] ^= 1 << j;
    }
  }
}

TEST(MLDSATest, Basic) {
  std::vector<uint8_t> encoded_public_key(MLDSA_PUBLIC_KEY_BYTES);
  auto priv = std::make_unique<MLDSA_private_key>();
  uint8_t seed[MLDSA_SEED_BYTES];
  EXPECT_TRUE(MLDSA_generate_key(encoded_public_key.data(), seed, priv.get()));

  std::vector<uint8_t> encoded_signature(MLDSA_SIGNATURE_BYTES);
  static const uint8_t kMessage[] = {'H', 'e', 'l', 'l', 'o', ' ',
                                     'w', 'o', 'r', 'l', 'd'};
  static const uint8_t kContext[] = {'c', 't', 'x'};
  EXPECT_TRUE(MLDSA_sign(encoded_signature.data(), priv.get(), kMessage,
                         sizeof(kMessage), kContext, sizeof(kContext)));

  auto pub = std::make_unique<MLDSA_public_key>();
  CBS cbs = bssl::MakeConstSpan(encoded_public_key);
  ASSERT_TRUE(MLDSA_parse_public_key(pub.get(), &cbs));

  EXPECT_EQ(MLDSA_verify(pub.get(), encoded_signature.data(),
                         encoded_signature.size(), kMessage, sizeof(kMessage),
                         kContext, sizeof(kContext)),
            1);

  auto priv2 = std::make_unique<MLDSA_private_key>();
  EXPECT_TRUE(MLDSA_private_key_from_seed(priv2.get(), seed));

  auto serialized_priv = CBBToVector(
      [&priv](CBB *cbb) { return MLDSA_marshal_private_key(cbb, priv.get()); });
  auto serialized_priv2 = CBBToVector([&priv2](CBB *cbb) {
    return MLDSA_marshal_private_key(cbb, priv2.get());
  });
  EXPECT_EQ(Bytes(serialized_priv), Bytes(serialized_priv2));
}

TEST(MLDSATest, SignatureIsRandomized) {
  std::vector<uint8_t> encoded_public_key(MLDSA_PUBLIC_KEY_BYTES);
  auto priv = std::make_unique<MLDSA_private_key>();
  EXPECT_TRUE(
      MLDSA_generate_key(encoded_public_key.data(), nullptr, priv.get()));

  auto pub = std::make_unique<MLDSA_public_key>();
  CBS cbs = bssl::MakeConstSpan(encoded_public_key);
  ASSERT_TRUE(MLDSA_parse_public_key(pub.get(), &cbs));

  std::vector<uint8_t> encoded_signature1(MLDSA_SIGNATURE_BYTES);
  std::vector<uint8_t> encoded_signature2(MLDSA_SIGNATURE_BYTES);
  static const uint8_t kMessage[] = {'H', 'e', 'l', 'l', 'o', ' ',
                                     'w', 'o', 'r', 'l', 'd'};
  EXPECT_TRUE(MLDSA_sign(encoded_signature1.data(), priv.get(), kMessage,
                         sizeof(kMessage), nullptr, 0));
  EXPECT_TRUE(MLDSA_sign(encoded_signature2.data(), priv.get(), kMessage,
                         sizeof(kMessage), nullptr, 0));

  EXPECT_NE(Bytes(encoded_signature1), Bytes(encoded_signature2));

  // Even though the signatures are different, they both verify.
  EXPECT_EQ(MLDSA_verify(pub.get(), encoded_signature1.data(),
                         encoded_signature1.size(), kMessage, sizeof(kMessage),
                         nullptr, 0),
            1);
  EXPECT_EQ(MLDSA_verify(pub.get(), encoded_signature2.data(),
                         encoded_signature2.size(), kMessage, sizeof(kMessage),
                         nullptr, 0),
            1);
}

TEST(MLDSATest, PublicFromPrivateIsConsistent) {
  std::vector<uint8_t> encoded_public_key(MLDSA_PUBLIC_KEY_BYTES);
  auto priv = std::make_unique<MLDSA_private_key>();
  EXPECT_TRUE(
      MLDSA_generate_key(encoded_public_key.data(), nullptr, priv.get()));

  auto pub = std::make_unique<MLDSA_public_key>();
  EXPECT_TRUE(MLDSA_public_from_private(pub.get(), priv.get()));

  std::vector<uint8_t> encoded_public_key2(MLDSA_PUBLIC_KEY_BYTES);

  CBB cbb;
  CBB_init_fixed(&cbb, encoded_public_key2.data(), encoded_public_key2.size());
  ASSERT_TRUE(MLDSA_marshal_public_key(&cbb, pub.get()));

  EXPECT_EQ(Bytes(encoded_public_key2), Bytes(encoded_public_key));
}

TEST(MLDSATest, InvalidPublicKeyEncodingLength) {
  // Encode a public key with a trailing 0 at the end.
  std::vector<uint8_t> encoded_public_key(MLDSA_PUBLIC_KEY_BYTES + 1);
  auto priv = std::make_unique<MLDSA_private_key>();
  EXPECT_TRUE(
      MLDSA_generate_key(encoded_public_key.data(), nullptr, priv.get()));

  // Public key is 1 byte too short.
  CBS cbs =
      bssl::MakeConstSpan(encoded_public_key).first(MLDSA_PUBLIC_KEY_BYTES - 1);
  auto parsed_pub = std::make_unique<MLDSA_public_key>();
  EXPECT_FALSE(MLDSA_parse_public_key(parsed_pub.get(), &cbs));

  // Public key has the correct length.
  cbs = bssl::MakeConstSpan(encoded_public_key).first(MLDSA_PUBLIC_KEY_BYTES);
  EXPECT_TRUE(MLDSA_parse_public_key(parsed_pub.get(), &cbs));

  // Public key is 1 byte too long.
  cbs = bssl::MakeConstSpan(encoded_public_key);
  EXPECT_FALSE(MLDSA_parse_public_key(parsed_pub.get(), &cbs));
}

TEST(MLDSATest, InvalidPrivateKeyEncodingLength) {
  std::vector<uint8_t> encoded_public_key(MLDSA_PUBLIC_KEY_BYTES);
  auto priv = std::make_unique<MLDSA_private_key>();
  EXPECT_TRUE(
      MLDSA_generate_key(encoded_public_key.data(), nullptr, priv.get()));

  CBB cbb;
  std::vector<uint8_t> malformed_private_key(MLDSA_PRIVATE_KEY_BYTES + 1, 0);
  CBB_init_fixed(&cbb, malformed_private_key.data(), MLDSA_PRIVATE_KEY_BYTES);
  ASSERT_TRUE(MLDSA_marshal_private_key(&cbb, priv.get()));

  CBS cbs;
  auto parsed_priv = std::make_unique<MLDSA_private_key>();

  // Private key is 1 byte too short.
  CBS_init(&cbs, malformed_private_key.data(), MLDSA_PRIVATE_KEY_BYTES - 1);
  EXPECT_FALSE(MLDSA_parse_private_key(parsed_priv.get(), &cbs));

  // Private key has the correct length.
  CBS_init(&cbs, malformed_private_key.data(), MLDSA_PRIVATE_KEY_BYTES);
  EXPECT_TRUE(MLDSA_parse_private_key(parsed_priv.get(), &cbs));

  // Private key is 1 byte too long.
  CBS_init(&cbs, malformed_private_key.data(), MLDSA_PRIVATE_KEY_BYTES + 1);
  EXPECT_FALSE(MLDSA_parse_private_key(parsed_priv.get(), &cbs));
}

static void MLDSASigGenTest(FileTest *t) {
  std::vector<uint8_t> private_key_bytes, msg, expected_signature;
  ASSERT_TRUE(t->GetBytes(&private_key_bytes, "sk"));
  ASSERT_TRUE(t->GetBytes(&msg, "message"));
  ASSERT_TRUE(t->GetBytes(&expected_signature, "signature"));

  auto priv = std::make_unique<MLDSA_private_key>();
  CBS cbs;
  CBS_init(&cbs, private_key_bytes.data(), private_key_bytes.size());
  EXPECT_TRUE(MLDSA_parse_private_key(priv.get(), &cbs));

  const uint8_t zero_randomizer[MLDSA_SIGNATURE_RANDOMIZER_BYTES] = {0};
  std::vector<uint8_t> signature(MLDSA_SIGNATURE_BYTES);
  EXPECT_TRUE(MLDSA_sign_internal(signature.data(), priv.get(), msg.data(),
                                  msg.size(), nullptr, 0, nullptr, 0,
                                  zero_randomizer));

  EXPECT_EQ(Bytes(signature), Bytes(expected_signature));

  auto pub = std::make_unique<MLDSA_public_key>();
  ASSERT_TRUE(MLDSA_public_from_private(pub.get(), priv.get()));
  EXPECT_TRUE(MLDSA_verify_internal(pub.get(), signature.data(), msg.data(),
                                    msg.size(), nullptr, 0, nullptr, 0));
}

TEST(MLDSATest, SigGenTests) {
  FileTestGTest("crypto/mldsa/mldsa_siggen_tests.txt", MLDSASigGenTest);
}

#if 0
// Disabled because the ACVP servers are incorrect and don't include the new
// bits in the final FIPS document.

static void MLDSAKeyGenTest(FileTest *t) {
  std::vector<uint8_t> seed, expected_public_key, expected_private_key;
  ASSERT_TRUE(t->GetBytes(&seed, "seed"));
  ASSERT_TRUE(t->GetBytes(&expected_public_key, "pub"));
  ASSERT_TRUE(t->GetBytes(&expected_private_key, "priv"));

  std::vector<uint8_t> encoded_public_key(MLDSA_PUBLIC_KEY_BYTES);
  auto priv = std::make_unique<MLDSA_private_key>();
  ASSERT_TRUE(MLDSA_generate_key_external_entropy(encoded_public_key.data(),
                                                  priv.get(), seed.data()));

  EXPECT_EQ(Bytes(encoded_public_key), Bytes(expected_public_key));
}

TEST(MLDSATest, KeyGenTests) {
  FileTestGTest("crypto/mldsa/mldsa_keygen_tests.txt", MLDSAKeyGenTest);
}
#endif

static void MLDSAWycheproofSignTest(FileTest *t) {
  std::vector<uint8_t> private_key_bytes, msg, expected_signature;
  ASSERT_TRUE(t->GetInstructionBytes(&private_key_bytes, "privateKey"));
  ASSERT_TRUE(t->GetBytes(&msg, "msg"));
  ASSERT_TRUE(t->GetBytes(&expected_signature, "sig"));
  std::string result;
  ASSERT_TRUE(t->GetAttribute(&result, "result"));
  t->IgnoreAttribute("flags");

  CBS cbs;
  CBS_init(&cbs, private_key_bytes.data(), private_key_bytes.size());
  auto priv = std::make_unique<MLDSA_private_key>();
  const int priv_ok = MLDSA_parse_private_key(priv.get(), &cbs);

  ASSERT_EQ(priv_ok, (result == "valid"));
  if (!priv_ok) {
    return;
  }

  const uint8_t zero_randomizer[MLDSA_SIGNATURE_RANDOMIZER_BYTES] = {0};
  std::vector<uint8_t> signature(MLDSA_SIGNATURE_BYTES);
  const uint8_t context_prefix[2] = {0, 0};
  EXPECT_TRUE(MLDSA_sign_internal(
      signature.data(), priv.get(), msg.data(), msg.size(), context_prefix,
      sizeof(context_prefix), nullptr, 0, zero_randomizer));

  EXPECT_EQ(Bytes(signature), Bytes(expected_signature));
}

TEST(MLDSATest, WycheproofSignTests) {
  FileTestGTest(
      "third_party/wycheproof_testvectors/mldsa_65_standard_sign_test.txt",
      MLDSAWycheproofSignTest);
}

static void MLDSAWycheproofVerifyTest(FileTest *t) {
  std::vector<uint8_t> public_key_bytes, msg, signature;
  ASSERT_TRUE(t->GetInstructionBytes(&public_key_bytes, "publicKey"));
  ASSERT_TRUE(t->GetBytes(&msg, "msg"));
  ASSERT_TRUE(t->GetBytes(&signature, "sig"));
  std::string result, flags;
  ASSERT_TRUE(t->GetAttribute(&result, "result"));
  ASSERT_TRUE(t->GetAttribute(&flags, "flags"));

  CBS cbs;
  CBS_init(&cbs, public_key_bytes.data(), public_key_bytes.size());
  auto pub = std::make_unique<MLDSA_public_key>();
  const int pub_ok = MLDSA_parse_public_key(pub.get(), &cbs);

  if (!pub_ok) {
    EXPECT_EQ(flags, "IncorrectPublicKeyLength");
    return;
  }

  const int sig_ok = MLDSA_verify(pub.get(), signature.data(), signature.size(),
                                  msg.data(), msg.size(), nullptr, 0);
  if (!sig_ok) {
    EXPECT_EQ(result, "invalid");
  } else {
    EXPECT_EQ(result, "valid");
  }
}

TEST(MLDSATest, WycheproofVerifyTests) {
  FileTestGTest(
      "third_party/wycheproof_testvectors/mldsa_65_standard_verify_test.txt",
      MLDSAWycheproofVerifyTest);
}

}  // namespace
