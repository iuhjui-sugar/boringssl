#include <gtest/gtest.h>
#include <fstream>

#include <openssl/mlkem.h>

#include "../keccak/internal.h"
#include "../test/file_test.h"
#include "../test/test_util.h"

using namespace std;

typedef vector<uint8_t> bytes;

TEST(MLKEM768Test, ConsistencyTest) {
  uint8_t randomness[64] = {0x37};
  uint8_t publicKey[MLKEM768_PUBLICKEYBYTES];
  uint8_t secretKey[MLKEM768_SECRETKEYBYTES];

  Libcrux_Mlkem768_GenerateKeyPair(publicKey, secretKey, randomness);

  uint8_t ciphertext[MLKEM768_CIPHERTEXTBYTES];
  uint8_t sharedSecret[MLKEM768_SHAREDSECRETBYTES];

  uint8_t encap_randomness[64] = {0x38};
  Libcrux_Mlkem768_Encapsulate(ciphertext, sharedSecret, &publicKey,
                               encap_randomness);

  uint8_t sharedSecret2[MLKEM768_SHAREDSECRETBYTES];
  Libcrux_Mlkem768_Decapsulate(sharedSecret2, &ciphertext, &secretKey);

  EXPECT_EQ(0, memcmp(sharedSecret, sharedSecret2, MLKEM768_SHAREDSECRETBYTES));
}

static void MlkemNistKatFileTest(FileTest *t) {
  bytes key_generation_seed, sha3_256_hash_of_public_key,
      sha3_256_hash_of_secret_key, encapsulation_seed,
      sha3_256_hash_of_ciphertext, shared_secret;

  ASSERT_TRUE(t->GetBytes(&key_generation_seed, "key_generation_seed"));
  ASSERT_TRUE(
      t->GetBytes(&sha3_256_hash_of_public_key, "sha3_256_hash_of_public_key"));
  ASSERT_TRUE(
      t->GetBytes(&sha3_256_hash_of_secret_key, "sha3_256_hash_of_secret_key"));
  ASSERT_TRUE(t->GetBytes(&encapsulation_seed, "encapsulation_seed"));
  ASSERT_TRUE(
      t->GetBytes(&sha3_256_hash_of_ciphertext, "sha3_256_hash_of_ciphertext"));
  ASSERT_TRUE(t->GetBytes(&shared_secret, "shared_secret"));

  uint8_t publicKey[MLKEM768_PUBLICKEYBYTES];
  uint8_t secretKey[MLKEM768_SECRETKEYBYTES];

  Libcrux_Mlkem768_GenerateKeyPair(publicKey, secretKey,
                                   key_generation_seed.data());


  uint8_t pk_hash[32];
  BORINGSSL_keccak(pk_hash, sizeof(pk_hash), publicKey, sizeof(publicKey),
                   boringssl_sha3_256);
  EXPECT_EQ(0, memcmp(pk_hash, sha3_256_hash_of_public_key.data(), 32));

  uint8_t sk_hash[32];
  BORINGSSL_keccak(sk_hash, sizeof(sk_hash), secretKey, sizeof(secretKey),
                   boringssl_sha3_256);
  EXPECT_EQ(0, memcmp(sk_hash, sha3_256_hash_of_secret_key.data(), 32));

  uint8_t ciphertext[MLKEM768_CIPHERTEXTBYTES];
  uint8_t sharedSecret[MLKEM768_SHAREDSECRETBYTES];
  Libcrux_Mlkem768_Encapsulate(ciphertext, sharedSecret, &publicKey,
                               encapsulation_seed.data());
  uint8_t ct_hash[32];
  BORINGSSL_keccak(ct_hash, sizeof(ct_hash), ciphertext, sizeof(ciphertext),
                   boringssl_sha3_256);
  EXPECT_EQ(0, memcmp(ct_hash, sha3_256_hash_of_ciphertext.data(), 32));
  EXPECT_EQ(0, memcmp(sharedSecret, shared_secret.data(),
                      MLKEM768_SHAREDSECRETBYTES));

  uint8_t sharedSecret2[MLKEM768_SHAREDSECRETBYTES];
  Libcrux_Mlkem768_Decapsulate(sharedSecret2, &ciphertext, &secretKey);

  EXPECT_EQ(0, memcmp(sharedSecret, sharedSecret2, MLKEM768_SHAREDSECRETBYTES));
}

TEST(MLKEM768TestNistKats, TestVectors) {
  FileTestGTest("crypto/mlkem/mlkem768_nistkats.txt", MlkemNistKatFileTest);
}

static void MlkemWycheproofKeygenFileTest(FileTest *t) {
  bytes entropy, expected_public_key, expected_private_key;

  t->IgnoreAttribute("comment");
  ASSERT_TRUE(t->GetBytes(&entropy, "entropy"));
  ASSERT_TRUE(t->GetBytes(&expected_public_key, "expected_public_key"));
  ASSERT_TRUE(t->GetBytes(&expected_private_key, "expected_private_key"));

  uint8_t publicKey[MLKEM768_PUBLICKEYBYTES];
  uint8_t secretKey[MLKEM768_SECRETKEYBYTES];

  Libcrux_Mlkem768_GenerateKeyPair(publicKey, secretKey, entropy.data());

  EXPECT_EQ(0, memcmp(publicKey, expected_public_key.data(),
                      MLKEM768_PUBLICKEYBYTES));
  EXPECT_EQ(0, memcmp(secretKey, expected_private_key.data(),
                      MLKEM768_SECRETKEYBYTES));
}

TEST(MLKEM768WycheproofKeygen, TestVectors) {
  FileTestGTest("crypto/mlkem/keygen768_wycheproof.txt",
                MlkemWycheproofKeygenFileTest);
}

static void MlkemWycheproofEncapsFileTest(FileTest *t) {
  bytes entropy, public_key, expected_ciphertext, expected_shared_secret;
  string expected_result;

  t->IgnoreAttribute("comment");
  ASSERT_TRUE(t->GetBytes(&entropy, "entropy"));
  ASSERT_TRUE(t->GetBytes(&public_key, "public_key"));
  ASSERT_TRUE(t->GetAttribute(&expected_result, "expected_result"));
  ASSERT_TRUE(t->GetBytes(&expected_ciphertext, "expected_ciphertext"));
  ASSERT_TRUE(t->GetBytes(&expected_shared_secret, "expected_shared_secret"));

  if (expected_result.compare("pass") == 0) {
    // Only passing tests here.
    uint8_t ciphertext[MLKEM768_CIPHERTEXTBYTES];
    uint8_t sharedSecret[MLKEM768_SHAREDSECRETBYTES];
    Libcrux_Mlkem768_Encapsulate(
        ciphertext, sharedSecret,
        reinterpret_cast<uint8_t(*)[MLKEM768_PUBLICKEYBYTES]>(
            public_key.data()),
        entropy.data());

    EXPECT_EQ(0, memcmp(ciphertext, expected_ciphertext.data(),
                        MLKEM768_CIPHERTEXTBYTES));
    EXPECT_EQ(0, memcmp(sharedSecret, expected_shared_secret.data(),
                        MLKEM768_SHAREDSECRETBYTES));
  } else {
    uint8_t pk[MLKEM768_PUBLICKEYBYTES];
    memcpy(pk, public_key.data(), MLKEM768_PUBLICKEYBYTES);
    auto valid = Libcrux_Mlkem768_ValidatePublicKey(pk);
    EXPECT_TRUE(!valid || public_key.size() != MLKEM768_PUBLICKEYBYTES);
  }
}

TEST(MLKEM768WycheproofEncaps, TestVectors) {
  FileTestGTest("crypto/mlkem/encaps768_wycheproof.txt",
                MlkemWycheproofEncapsFileTest);
}


static void MlkemWycheproofDecapsFileTest(FileTest *t) {
  bytes private_key, ciphertext, expected_shared_secret;
  string expected_result;

  t->IgnoreAttribute("comment");
  ASSERT_TRUE(t->GetBytes(&private_key, "private_key"));
  ASSERT_TRUE(t->GetBytes(&ciphertext, "ciphertext"));
  ASSERT_TRUE(t->GetAttribute(&expected_result, "expected_result"));
  ASSERT_TRUE(t->GetBytes(&expected_shared_secret, "expected_shared_secret"));

  if (expected_result.compare("pass") == 0) {
    // Only passing tests here.
    uint8_t sharedSecret[MLKEM768_SHAREDSECRETBYTES];
    Libcrux_Mlkem768_Decapsulate(
        sharedSecret,
        reinterpret_cast<uint8_t(*)[MLKEM768_CIPHERTEXTBYTES]>(
            ciphertext.data()),
        reinterpret_cast<uint8_t(*)[MLKEM768_SECRETKEYBYTES]>(
            private_key.data()));

    EXPECT_EQ(0, memcmp(sharedSecret, expected_shared_secret.data(),
                        MLKEM768_SHAREDSECRETBYTES));
  } else {
    // We don't check private keys.
  }
}

TEST(MLKEM768WycheproofDecaps, TestVectors) {
  FileTestGTest("crypto/mlkem/decaps768_wycheproof.txt",
                MlkemWycheproofDecapsFileTest);
}
