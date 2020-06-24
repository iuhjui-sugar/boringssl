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
#include <string>
#include <vector>

#include "../test/file_test.h"
#include "../test/test_util.h"
#include "internal.h"

namespace {

// HpkeTestVector corresponds to the JSON schema used in the published
// test-vectors.json.
struct HpkeTestVector {
  struct Encryption {
    std::vector<uint8_t> aad;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> plaintext;
  };
  struct Export {
    std::vector<uint8_t> exportContext;
    size_t exportLength;
    std::vector<uint8_t> exportValue;
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
  std::vector<uint8_t> public_key_r;
  std::vector<uint8_t> secret;
  std::vector<uint8_t> secret_key_e;
  std::vector<uint8_t> secret_key_r;
  std::vector<uint8_t> zz;
  std::vector<Encryption> encryptions;
  std::vector<Export> exports;
};

void hpke_ephemeral_keypair_set(EVP_HPKE_CTX *hpke,
                                const uint8_t priv[X25519_PRIVATE_KEY_LEN]);
void VerifyParameters(const EVP_HPKE_CTX &hpke, const HpkeTestVector &vec,
                      const std::string &debug_label);
void VerifyEncryptions(const HpkeTestVector &vec, EVP_HPKE_CTX *sender_ctx,
                       EVP_HPKE_CTX *receiver_ctx);
void RunTestVector(const HpkeTestVector &vec);

void hpke_ephemeral_keypair_set(EVP_HPKE_CTX *hpke,
                                const uint8_t priv[X25519_PRIVATE_KEY_LEN]) {
  OPENSSL_memcpy(hpke->secret_key_ephemeral, priv, X25519_PRIVATE_KEY_LEN);
  hpke->secret_key_ephemeral_len = X25519_PRIVATE_KEY_LEN;
}

void VerifyParameters(const EVP_HPKE_CTX &hpke, const HpkeTestVector &vec,
                      const std::string &debug_label) {
  EXPECT_LE(vec.nonce.size(), sizeof(hpke.nonce));
  EXPECT_EQ(Bytes(hpke.nonce, vec.nonce.size()), Bytes(vec.nonce))
      << debug_label;

  EXPECT_LE(vec.exporter_secret.size(), sizeof(hpke.exporter_secret));
  EXPECT_EQ(Bytes(hpke.exporter_secret, vec.exporter_secret.size()),
            Bytes(vec.exporter_secret))
      << debug_label;
}

void VerifyEncryptions(const HpkeTestVector &vec, EVP_HPKE_CTX *sender_ctx,
                       EVP_HPKE_CTX *receiver_ctx) {
  for (HpkeTestVector::Encryption task : vec.encryptions) {
    // Allocate a buffer for the result of seal().
    std::vector<uint8_t> encrypted(task.plaintext.size() +
                                   EVP_AEAD_MAX_OVERHEAD);
    size_t encrypted_len;

    EXPECT_TRUE(EVP_HPKE_CTX_seal(sender_ctx, encrypted.data(), &encrypted_len,
                                  encrypted.size(), task.plaintext.data(),
                                  task.plaintext.size(), task.aad.data(),
                                  task.aad.size()));

    EXPECT_EQ(Bytes(encrypted.data(), encrypted_len), Bytes(task.ciphertext));

    std::vector<uint8_t> decrypted(task.ciphertext.size());
    size_t decrypted_len;

    EXPECT_TRUE(EVP_HPKE_CTX_open(
        receiver_ctx, decrypted.data(), &decrypted_len, decrypted.size(),
        task.ciphertext.data(), task.ciphertext.size(), task.aad.data(),
        task.aad.size()));

    EXPECT_EQ(Bytes(decrypted.data(), decrypted_len), Bytes(task.plaintext));
  }
}

void VerifyExports(const HpkeTestVector &vec, EVP_HPKE_CTX *ctx) {
  for (const auto &exp : vec.exports) {
    std::vector<uint8_t> exported_secret(exp.exportLength);

    ASSERT_TRUE(EVP_HPKE_CTX_export(
        ctx, exported_secret.data(), exported_secret.size(),
        exp.exportContext.data(), exp.exportContext.size()));
    EXPECT_EQ(Bytes(exported_secret), Bytes(exp.exportValue));
  }
}

void RunTestVector(const HpkeTestVector &vec) {
  // Set up the sender.
  EVP_HPKE_CTX sender_ctx;
  EVP_HPKE_CTX_init(&sender_ctx);
  ASSERT_GT(vec.secret_key_e.size(), 0u);
  hpke_ephemeral_keypair_set(&sender_ctx, vec.secret_key_e.data());

  uint8_t enc[X25519_PUBLIC_VALUE_LEN];
  EXPECT_TRUE(EVP_HPKE_CTX_setup_base_x25519_s(
      &sender_ctx, enc, vec.aead_id, vec.public_key_r.data(), vec.info.data(),
      vec.info.size()));

  // Verify that |enc| matches test vector.
  EXPECT_EQ(Bytes(enc, sizeof(enc)), Bytes(vec.enc));

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
  VerifyExports(vec, &sender_ctx);
  VerifyExports(vec, &receiver_ctx);

  EVP_HPKE_CTX_cleanup(&sender_ctx);
  EVP_HPKE_CTX_cleanup(&receiver_ctx);
}

template <typename T>
void FileTestReadInt(FileTest *t, T *out, const std::string &key) {
  std::string tmp;
  ASSERT_TRUE(t->GetAttribute(&tmp, key));
  *out = std::stoi(tmp);
}

std::string BuildAttrName(const std::string &name, int iter) {
  return iter == 1 ? name : name + "/" + std::to_string(iter);
};

bool DeriveX25519Keypair(const EVP_MD *hkdf_md,
                         std::vector<uint8_t> *out_private,
                         std::vector<uint8_t> *out_public,
                         const std::vector<uint8_t> &ikm) {
  out_private->resize(X25519_PRIVATE_KEY_LEN);
  out_public->resize(X25519_PUBLIC_VALUE_LEN);
  return EVP_HPKE_derive_x25519_keypair(hkdf_md, out_private->data(),
                                        out_public->data(), ikm.data(),
                                        ikm.size()) == 1;
}

}  // namespace

TEST(HPKETest, ReadFileTest) {
  FileTestGTest("crypto/hpke/hpke_test_vectors.txt", [](FileTest *t) {
    HpkeTestVector test_vec;
    t->IgnoreInstruction("test");

    FileTestReadInt(t, &test_vec.mode, "mode");
    FileTestReadInt(t, &test_vec.kem_id, "kemID");
    FileTestReadInt(t, &test_vec.kdf_id, "kdfID");
    FileTestReadInt(t, &test_vec.aead_id, "aeadID");

    ASSERT_TRUE(t->GetBytes(&test_vec.info, "info"));

    std::vector<uint8_t> seed_r;
    ASSERT_TRUE(t->GetBytes(&seed_r, "seedR"));
    ASSERT_TRUE(DeriveX25519Keypair(EVP_sha256(), &test_vec.secret_key_r,
                                    &test_vec.public_key_r, seed_r));

    std::vector<uint8_t> seed_e;
    ASSERT_TRUE(t->GetBytes(&seed_e, "seedE"));
    std::vector<uint8_t> public_key_e_ignored;
    ASSERT_TRUE(DeriveX25519Keypair(EVP_sha256(), &test_vec.secret_key_e,
                                    &public_key_e_ignored, seed_e));

    ASSERT_TRUE(t->GetBytes(&test_vec.enc, "enc"));
    ASSERT_TRUE(t->GetBytes(&test_vec.zz, "zz"));
    ASSERT_TRUE(t->GetBytes(&test_vec.context, "keyScheduleContext"));
    ASSERT_TRUE(t->GetBytes(&test_vec.secret, "secret"));
    ASSERT_TRUE(t->GetBytes(&test_vec.key, "key"));
    ASSERT_TRUE(t->GetBytes(&test_vec.nonce, "outer_nonce"));
    ASSERT_TRUE(t->GetBytes(&test_vec.exporter_secret, "exporterSecret"));

    for (int i = 1; t->HasAttribute(BuildAttrName("aad", i)); i++) {
      HpkeTestVector::Encryption encryption;
      ASSERT_TRUE(t->GetBytes(&encryption.aad, BuildAttrName("aad", i)));
      ASSERT_TRUE(
          t->GetBytes(&encryption.ciphertext, BuildAttrName("ciphertext", i)));
      ASSERT_TRUE(t->GetBytes(&encryption.nonce, BuildAttrName("nonce", i)));
      ASSERT_TRUE(
          t->GetBytes(&encryption.plaintext, BuildAttrName("plaintext", i)));
      test_vec.encryptions.push_back(std::move(encryption));
    }

    for (int i = 1; t->HasAttribute(BuildAttrName("exportContext", i)); i++) {
      HpkeTestVector::Export exp;
      ASSERT_TRUE(
          t->GetBytes(&exp.exportContext, BuildAttrName("exportContext", i)));
      FileTestReadInt(t, &exp.exportLength, BuildAttrName("exportLength", i));
      ASSERT_TRUE(
          t->GetBytes(&exp.exportValue, BuildAttrName("exportValue", i)));
      test_vec.exports.push_back(std::move(exp));
    }

    RunTestVector(test_vec);
  });
}
