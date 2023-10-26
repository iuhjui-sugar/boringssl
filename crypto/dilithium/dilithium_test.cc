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

#include <string.h>

#include <gtest/gtest.h>

#include <openssl/bytestring.h>
#include <openssl/ctrdrbg.h>
#include <openssl/dilithium.h>

#include "../test/file_test.h"
#include "../test/test_util.h"
#include "./internal.h"


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

TEST(DilithiumTest, BitFlips) {
  uint8_t encoded_public_key[DILITHIUM_PUBLIC_KEY_BYTES];
  DILITHIUM_private_key priv;
  DILITHIUM_generate_key(encoded_public_key, &priv);

  uint8_t encoded_signature[DILITHIUM_SIGNATURE_BYTES];
  const char *message = "Hello world";
  DILITHIUM_sign_deterministic(encoded_signature, &priv,
                               (const uint8_t *)message, strlen(message));

  DILITHIUM_public_key pub;
  CBS cbs;
  CBS_init(&cbs, encoded_public_key, sizeof(encoded_public_key));
  ASSERT_TRUE(DILITHIUM_parse_public_key(&pub, &cbs));

  EXPECT_EQ(DILITHIUM_verify(&pub, encoded_signature, (const uint8_t *)message,
                             strlen(message)),
            1);

  for (size_t i = 0; i < DILITHIUM_SIGNATURE_BYTES; i++) {
    for (int j = 0; j < 8; j++) {
      encoded_signature[i] ^= 1 << j;
      EXPECT_EQ(DILITHIUM_verify(&pub, encoded_signature,
                                 (const uint8_t *)message, strlen(message)),
                0)
          << "Bit flip in signature at byte " << i << " bit " << j
          << " didn't cause a verification failure";
      encoded_signature[i] ^= 1 << j;
    }
  }
}

// TODO(guillaumee): Test parsing.

static void DilithiumFileTest(FileTest *t) {
  std::vector<uint8_t> seed, message, public_key_expected, private_key_expected,
      signed_message_expected;
  t->IgnoreAttribute("count");
  ASSERT_TRUE(t->GetBytes(&seed, "seed"));
  t->IgnoreAttribute("mlen");
  ASSERT_TRUE(t->GetBytes(&message, "msg"));
  ASSERT_TRUE(t->GetBytes(&public_key_expected, "pk"));
  ASSERT_TRUE(t->GetBytes(&private_key_expected, "sk"));
  t->IgnoreAttribute("smlen");
  ASSERT_TRUE(t->GetBytes(&signed_message_expected, "sm"));

  uint8_t gen_key_entropy[DILITHIUM_GENERATE_KEY_ENTROPY];
  // The test vectors provide a CTR-DRBG seed which is used to generate the
  // input entropy.
  ASSERT_EQ(seed.size(), size_t{CTR_DRBG_ENTROPY_LEN});
  {
    bssl::UniquePtr<CTR_DRBG_STATE> state(
        CTR_DRBG_new(seed.data(), nullptr, 0));
    ASSERT_TRUE(state);
    ASSERT_TRUE(CTR_DRBG_generate(state.get(), gen_key_entropy,
                                  DILITHIUM_GENERATE_KEY_ENTROPY, nullptr, 0));
  }

  // Reproduce key generation.
  DILITHIUM_public_key parsed_pub;
  DILITHIUM_private_key priv;
  uint8_t encoded_private_key[DILITHIUM_PRIVATE_KEY_BYTES];
  uint8_t encoded_public_key[DILITHIUM_PUBLIC_KEY_BYTES];

  DILITHIUM_generate_key_external_entropy(encoded_public_key, &priv,
                                          gen_key_entropy);

  CBB cbb;
  CBB_init_fixed(&cbb, encoded_private_key, sizeof(encoded_private_key));
  ASSERT_TRUE(DILITHIUM_marshal_private_key(&cbb, &priv));

  EXPECT_EQ(Bytes(encoded_public_key), Bytes(public_key_expected));
  EXPECT_EQ(Bytes(encoded_private_key), Bytes(private_key_expected));

  // Reproduce signature.
  uint8_t encoded_signature[DILITHIUM_SIGNATURE_BYTES];
  DILITHIUM_sign_deterministic(encoded_signature, &priv, message.data(),
                               message.size());

  EXPECT_EQ(Bytes(encoded_signature),
            Bytes(signed_message_expected.data(), DILITHIUM_SIGNATURE_BYTES));
  EXPECT_EQ(Bytes(message),
            Bytes(&signed_message_expected[DILITHIUM_SIGNATURE_BYTES],
                  signed_message_expected.size() - DILITHIUM_SIGNATURE_BYTES));

  // Check that verification matches.
  CBS cbs;
  CBS_init(&cbs, encoded_public_key, sizeof(encoded_public_key));
  ASSERT_TRUE(DILITHIUM_parse_public_key(&parsed_pub, &cbs));
  EXPECT_EQ(DILITHIUM_verify(&parsed_pub, encoded_signature, message.data(),
                             message.size()),
            1);

  // Test that parsing the encoded private key yields a functional object.
  DILITHIUM_private_key parsed_priv;
  uint8_t encoded_signature2[DILITHIUM_SIGNATURE_BYTES];

  CBS_init(&cbs, encoded_private_key, sizeof(encoded_private_key));
  ASSERT_TRUE(DILITHIUM_parse_private_key(&parsed_priv, &cbs));

  DILITHIUM_sign_deterministic(encoded_signature2, &parsed_priv, message.data(),
                               message.size());
  EXPECT_EQ(Bytes(encoded_signature2), Bytes(encoded_signature));

  // Test that parsing + encoding is idempotent.
  uint8_t encoded_private_key2[DILITHIUM_PRIVATE_KEY_BYTES];
  uint8_t encoded_public_key2[DILITHIUM_PUBLIC_KEY_BYTES];

  CBB_init_fixed(&cbb, encoded_private_key2, sizeof(encoded_private_key2));
  ASSERT_TRUE(DILITHIUM_marshal_private_key(&cbb, &parsed_priv));
  CBB_init_fixed(&cbb, encoded_public_key2, sizeof(encoded_public_key2));
  ASSERT_TRUE(DILITHIUM_marshal_public_key(&cbb, &parsed_pub));

  EXPECT_EQ(Bytes(encoded_public_key2), Bytes(encoded_public_key));
  EXPECT_EQ(Bytes(encoded_private_key2), Bytes(encoded_private_key));
}

TEST(DilithiumTest, TestVectors) {
  FileTestGTest("crypto/dilithium/dilithium_tests.txt", DilithiumFileTest);
}
