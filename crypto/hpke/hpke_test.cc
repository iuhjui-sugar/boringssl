/* Copyright (c) 2020, Google Inc.
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
#include <openssl/aead.h>
#include <openssl/base.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include <cstdint>
#include <vector>

#include "../test/file_test.h"
#include "../test/test_util.h"
#include "internal.h"

struct HpkeTestVector {
  struct Encryption {
    std::vector<uint8_t> aad;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> plaintext;
  };

  uint8_t mode;
  uint16_t kem_id;
  uint16_t kdf_id;
  uint16_t aead_id;
  std::vector<uint8_t> context;
  std::vector<uint8_t> enc;
  std::vector<uint8_t> exporter_secret;
  std::vector<uint8_t> info;
  std::vector<uint8_t> key;
  std::vector<uint8_t> nonce;
  std::vector<uint8_t> public_key_e;
  std::vector<uint8_t> public_key_r;
  std::vector<uint8_t> secret;
  std::vector<uint8_t> secret_key_e;
  std::vector<uint8_t> secret_key_r;
  std::vector<uint8_t> zz;
  std::vector<Encryption> encryptions;
};

std::vector<uint8_t> ParseHex(std::string hex);
void hpke_ephemeral_keypair_set(EVP_HPKE_CTX* hpke,
                                const uint8_t priv[X25519_PRIVATE_KEY_LEN]);
void VerifyParameters(const EVP_HPKE_CTX& hpke, const HpkeTestVector& vec,
                      const std::string& debug_label);
void RunTestVector(const HpkeTestVector& vec);

std::vector<uint8_t> ParseHex(std::string hex) {
  std::vector<uint8_t> decoded;
  DecodeHex(&decoded, hex);
  return decoded;
}

const HpkeTestVector kTestVectorBaseSetup{
    0 /* mode */,
    32 /* kem_id */,
    1 /* kdf_id */,
    1 /* aead_id */,
    ParseHex("002000010001005d0f5548cb13d7eba5320ae0e21b1ee274aac7ea1cce025"
             "70cf993d1b2456449debcca602075cf6f8ef506613a82e1c73727e2c912d0"
             "c49f16cd56fc524af4ce") /* context */,
    ParseHex("052bd1295cfdb689d355b1b7b7ceba37c678cde1f6a064ef34b9311b34af8"
             "e6e") /* enc */,
    ParseHex("29043e917d24904aa2273943136b33d58c432338f79c0ff787e34c943eb23"
             "547") /* exporter_secret */,
    ParseHex("4f6465206f6e2061204772656369616e2055726e") /* info */,
    ParseHex("c2bcebf9370d42f0a86161475b76b36c") /* key */,
    ParseHex("1560742d89f5977209e92107") /* nonce */,
    ParseHex("052bd1295cfdb689d355b1b7b7ceba37c678cde1f6a064ef34b9311b34af8"
             "e6e") /* public_key_e */,
    ParseHex("241b10c2782f0e33de4bec7e9fc01100eb75abd4f7b2bcd537a6741e7a468"
             "c5c") /* public_key_r */,
    ParseHex("4aa0461853aea86a88bec45abc2c50e7b0ad0b0a0cb96cb40961d1e02723f"
             "961") /* secret */,
    ParseHex("f62208406d0cf52260498212955a6618f0ff9efefde4726358af6810607c2"
             "f4d") /* secret_key_e */,
    ParseHex("e162d7990e1f5a2364a1bf77a4c90e6ea64c9502b2a389378b590f121a600"
             "06f") /* secret_key_r */,
    ParseHex("d0ea477c17447da90484d89719e8da8834124215b5c4f932b8328f8034665"
             "f46") /* zz */,
    {
        HpkeTestVector::Encryption{
            ParseHex("436f756e742d30") /* aad */,
            ParseHex(
                "4fc6ba1098883e69be8afde90d480b935e1cb7f472ebf8982b57ce57f0"
                "f73d05aba2ccd79a347426a20b02514f") /* ciphertext */,
            ParseHex("1560742d89f5977209e92107") /* nonce */,
            ParseHex("4265617574792069732074727574682c207472757468206265617"
                     "57479") /* plaintext */,
        },
        HpkeTestVector::Encryption{
            ParseHex("436f756e742d31") /* aad */,
            ParseHex(
                "e6a18d5cf2e642741b0c48d237c7d9a3fad0aa39261bd36e84a422014e"
                "8b15455504e5782eb4c348977563f300") /* ciphertext */,
            ParseHex("1560742d89f5977209e92106") /* nonce */,
            ParseHex("4265617574792069732074727574682c207472757468206265617"
                     "57479") /* plaintext */,
        },
        HpkeTestVector::Encryption{
            ParseHex("436f756e742d32") /* aad */,
            ParseHex(
                "fe27c724465e83a3eea38f2c7f0186b5b9bfc68db2842757bed2aa24b4"
                "848a3935d4dd709ed4205bce5b4e7381") /* ciphertext */,
            ParseHex("1560742d89f5977209e92105") /* nonce */,
            ParseHex("4265617574792069732074727574682c207472757468206265617"
                     "57479") /* plaintext */,
        },
        HpkeTestVector::Encryption{
            ParseHex("436f756e742d33") /* aad */,
            ParseHex(
                "1a8cb701370e2bf42693f208929f54e638844364a250682947ca027a6e"
                "c8376cba872b8781bd92777638805273") /* ciphertext */,
            ParseHex("1560742d89f5977209e92104") /* nonce */,
            ParseHex("4265617574792069732074727574682c207472757468206265617"
                     "57479") /* plaintext */,
        },
        HpkeTestVector::Encryption{
            ParseHex("436f756e742d34") /* aad */,
            ParseHex(
                "7d697f0119b1b94518df0a0a666e38e057c317193064bfc2dd823b9a28"
                "09c64961396f5b2668aa6a743dcfc1e3") /* ciphertext */,
            ParseHex("1560742d89f5977209e92103") /* nonce */,
            ParseHex("4265617574792069732074727574682c207472757468206265617"
                     "57479") /* plaintext */,
        },
        HpkeTestVector::Encryption{
            ParseHex("436f756e742d35") /* aad */,
            ParseHex(
                "e251e12eb7755b00525cb2c1fcdce0be973d32e510b0dc519c1826bee7"
                "a8cb087e97a09999c27a1485e12a7944") /* ciphertext */,
            ParseHex("1560742d89f5977209e92102") /* nonce */,
            ParseHex("4265617574792069732074727574682c207472757468206265617"
                     "57479") /* plaintext */,
        },
        HpkeTestVector::Encryption{
            ParseHex("436f756e742d36") /* aad */,
            ParseHex(
                "4391039266fcfdaaa919b71d4856f878e655b1de9aa31b3aae2ccb2d1e"
                "d0df9344a3650cf501da088eea69d393") /* ciphertext */,
            ParseHex("1560742d89f5977209e92101") /* nonce */,
            ParseHex("4265617574792069732074727574682c207472757468206265617"
                     "57479") /* plaintext */,
        },
        HpkeTestVector::Encryption{
            ParseHex("436f756e742d37") /* aad */,
            ParseHex(
                "68efdff7231c75d6aeb2b3d198bdb01c292e524bc44ffc880bb29ad75f"
                "af0d68a0bfcbf38db826709ddda5a8f2") /* ciphertext */,
            ParseHex("1560742d89f5977209e92100") /* nonce */,
            ParseHex("4265617574792069732074727574682c207472757468206265617"
                     "57479") /* plaintext */,
        },
        HpkeTestVector::Encryption{
            ParseHex("436f756e742d38") /* aad */,
            ParseHex(
                "298dadf8253f5a3ceb9442aae8b707605daf6c53cee389d227ef7a181d"
                "ecb369aefe64bdda4b6a5b6663225a58") /* ciphertext */,
            ParseHex("1560742d89f5977209e9210f") /* nonce */,
            ParseHex("4265617574792069732074727574682c207472757468206265617"
                     "57479") /* plaintext */,
        },
        HpkeTestVector::Encryption{
            ParseHex("436f756e742d39") /* aad */,
            ParseHex(
                "783f50f81d1519bcb5eeb5288cc721e7222e57569ff2165aefd68cc1f9"
                "2c8f5068c156c7fa5726d7b3695a6b5d") /* ciphertext */,
            ParseHex("1560742d89f5977209e9210e") /* nonce */,
            ParseHex("4265617574792069732074727574682c207472757468206265617"
                     "57479") /* plaintext */,
        },
    }};

void hpke_ephemeral_keypair_set(EVP_HPKE_CTX* hpke,
                                const uint8_t priv[X25519_PRIVATE_KEY_LEN]) {
  OPENSSL_memcpy(hpke->secret_key_ephemeral, priv, X25519_PRIVATE_KEY_LEN);
  hpke->secret_key_ephemeral_len = X25519_PRIVATE_KEY_LEN;
}

// void PrintExpected(const std::string& debug_label,
//                    bssl::Span<const uint8_t> data) {
//   LOG(ERROR) << "expected [" << data.size() << " bytes] " << debug_label << "\n"
//              << EncodeHex(data);
// }

void VerifyParameters(const EVP_HPKE_CTX& hpke, const HpkeTestVector& vec,
                      const std::string& debug_label) {
  // PrintExpected("context", vec.context);
  // PrintExpected("secret", vec.secret);
  // PrintExpected("nonce", vec.nonce);
  // PrintExpected("key", vec.key);

  EXPECT_LE(vec.nonce.size(), sizeof(hpke.nonce));
  EXPECT_EQ(Bytes(hpke.nonce, vec.nonce.size()), Bytes(vec.nonce))
      << debug_label;

  EXPECT_LE(vec.exporter_secret.size(), sizeof(hpke.exporter_secret));
  EXPECT_EQ(Bytes(hpke.exporter_secret, vec.exporter_secret.size()),
            Bytes(vec.exporter_secret))
      << debug_label;
}

void VerifyEncryptions(const HpkeTestVector& vec, EVP_HPKE_CTX* sender_ctx,
                       EVP_HPKE_CTX* receiver_ctx) {
  // int task_num = 0;

  for (HpkeTestVector::Encryption task : vec.encryptions) {
    // LOG(ERROR) << "task_num = " << task_num;
    // task_num++;

    // Allocate a buffer for the result of seal().
    std::vector<uint8_t> encrypted;
    encrypted.resize(task.plaintext.size() + EVP_AEAD_MAX_OVERHEAD);
    size_t encrypted_len;

    EXPECT_TRUE(EVP_HPKE_CTX_seal(sender_ctx, encrypted.data(), &encrypted_len,
                                  encrypted.size(), task.plaintext.data(),
                                  task.plaintext.size(), task.aad.data(),
                                  task.aad.size()));

    EXPECT_EQ(bssl::Span<const uint8_t>(encrypted.data(), encrypted_len),
              bssl::Span<const uint8_t>(task.ciphertext));

    std::vector<uint8_t> decrypted;
    decrypted.resize(task.ciphertext.size());
    size_t decrypted_len;

    EXPECT_TRUE(EVP_HPKE_CTX_open(
        receiver_ctx, decrypted.data(), &decrypted_len, decrypted.size(),
        task.ciphertext.data(), task.ciphertext.size(), task.aad.data(),
        task.aad.size()));

    EXPECT_EQ(bssl::Span<const uint8_t>(decrypted.data(), decrypted_len),
              bssl::Span<const uint8_t>(task.plaintext));
  }
}

void RunTestVector(const HpkeTestVector& vec) {
  // Set up the sender.
  EVP_HPKE_CTX sender_ctx;
  EVP_HPKE_CTX_init(&sender_ctx);
  hpke_ephemeral_keypair_set(&sender_ctx, vec.secret_key_e.data());

  uint8_t enc[X25519_PUBLIC_VALUE_LEN];
  EXPECT_TRUE(EVP_HPKE_CTX_setup_base_x25519_s(
      &sender_ctx, enc, vec.aead_id, vec.public_key_r.data(), vec.info.data(),
      vec.info.size()));

  // Verify that |enc| matches test vector.
  EXPECT_EQ(bssl::Span<const uint8_t>(enc, sizeof(enc)),
            bssl::Span<const uint8_t>(vec.enc.data(), vec.enc.size()));

  VerifyParameters(sender_ctx, vec, "Sender");

  // Set up the receiver.
  EVP_HPKE_CTX receiver_ctx;
  EVP_HPKE_CTX_init(&receiver_ctx);
  hpke_ephemeral_keypair_set(&receiver_ctx, vec.secret_key_e.data());

  EXPECT_TRUE(EVP_HPKE_CTX_setup_base_x25519_r(
      &receiver_ctx, vec.aead_id, enc, vec.secret_key_r.data(), vec.info.data(),
      vec.info.size()));

  VerifyParameters(receiver_ctx, vec, "Receiver");
  VerifyEncryptions(vec, &sender_ctx, &receiver_ctx);

  EVP_HPKE_CTX_cleanup(&sender_ctx);
  EVP_HPKE_CTX_cleanup(&receiver_ctx);
}

TEST(HPKETest, TestVectors) { RunTestVector(kTestVectorBaseSetup); }
