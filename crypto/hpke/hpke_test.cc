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

// DeriveX25519Keypair is a convenience wrapper around
// |EVP_HPKE_derive_x25519_keypair|.
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

// Just a duplicate of the function with the same name in hpke.c. This enables
// us to avoid exporting the function.
void hpke_ephemeral_keypair_set(EVP_HPKE_CTX *hpke,
                                const uint8_t priv[X25519_PRIVATE_KEY_LEN]) {
  OPENSSL_memcpy(hpke->secret_key_ephemeral, priv, X25519_PRIVATE_KEY_LEN);
  hpke->secret_key_ephemeral_len = X25519_PRIVATE_KEY_LEN;
}

// HpkeTestVector corresponds to one array member in the published
// test-vectors.json.
class HpkeTestVector {
 public:
  explicit HpkeTestVector(FileTest *t);
  ~HpkeTestVector() = default;

  void Verify() const {
    // Set up the sender.
    EVP_HPKE_CTX sender_ctx;
    EVP_HPKE_CTX_init(&sender_ctx);
    ASSERT_GT(secret_key_e_.size(), 0u);
    hpke_ephemeral_keypair_set(&sender_ctx, secret_key_e_.data());

    uint8_t enc[X25519_PUBLIC_VALUE_LEN];
    EXPECT_TRUE(EVP_HPKE_CTX_setup_base_x25519_s(&sender_ctx, enc, aead_id_,
                                                 public_key_r_.data(),
                                                 info_.data(), info_.size()));
    // Verify that the computed |enc| matches the expected |enc_|.
    EXPECT_EQ(Bytes(enc), Bytes(enc_));
    VerifyParameters(sender_ctx, "Sender");

    // Set up the receiver.
    EVP_HPKE_CTX receiver_ctx;
    EVP_HPKE_CTX_init(&receiver_ctx);
    hpke_ephemeral_keypair_set(&receiver_ctx, secret_key_e_.data());

    EXPECT_TRUE(EVP_HPKE_CTX_setup_base_x25519_r(&receiver_ctx, aead_id_, enc,
                                                 secret_key_r_.data(),
                                                 info_.data(), info_.size()));
    VerifyParameters(receiver_ctx, "Receiver");

    VerifyEncryptions(&sender_ctx, &receiver_ctx);
    VerifyExports(&sender_ctx);
    VerifyExports(&receiver_ctx);

    EVP_HPKE_CTX_cleanup(&sender_ctx);
    EVP_HPKE_CTX_cleanup(&receiver_ctx);
  }

 private:
  void VerifyParameters(const EVP_HPKE_CTX &hpke,
                        const std::string &debug_label) const {
    // The first N bytes of |hpke.nonce| should match the expected |nonce_|.
    EXPECT_LE(nonce_.size(), sizeof(hpke.nonce));
    EXPECT_EQ(Bytes(hpke.nonce, nonce_.size()), Bytes(nonce_)) << debug_label;

    // The first N bytes of |hpke.exporter_secret| should match the expected
    // |exporter_secret_|.
    EXPECT_LE(exporter_secret_.size(), sizeof(hpke.exporter_secret));
    EXPECT_EQ(Bytes(hpke.exporter_secret, exporter_secret_.size()),
              Bytes(exporter_secret_))
        << debug_label;
  }

  void VerifyEncryptions(EVP_HPKE_CTX *sender_ctx,
                         EVP_HPKE_CTX *receiver_ctx) const {
    for (const Encryption &task : encryptions_) {
      // Allocate a buffer for the result of seal().
      std::vector<uint8_t> encrypted(task.plaintext.size() +
                                     EVP_AEAD_MAX_OVERHEAD);
      size_t encrypted_len;
      EXPECT_TRUE(EVP_HPKE_CTX_seal(
          sender_ctx, encrypted.data(), &encrypted_len, encrypted.size(),
          task.plaintext.data(), task.plaintext.size(), task.aad.data(),
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

  void VerifyExports(EVP_HPKE_CTX *ctx) const {
    for (const Export &task : exports_) {
      std::vector<uint8_t> exported_secret(task.exportLength);

      ASSERT_TRUE(EVP_HPKE_CTX_export(
          ctx, exported_secret.data(), exported_secret.size(),
          task.exportContext.data(), task.exportContext.size()));
      EXPECT_EQ(Bytes(exported_secret), Bytes(task.exportValue));
    }
  }

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

  uint8_t mode_;
  uint16_t kem_id_;
  uint16_t kdf_id_;
  uint16_t aead_id_;
  std::vector<uint8_t> context_;
  std::vector<uint8_t> enc_;
  std::vector<uint8_t> exporter_secret_;
  std::vector<uint8_t> info_;
  std::vector<uint8_t> key_;
  std::vector<uint8_t> nonce_;
  std::vector<uint8_t> public_key_r_;
  std::vector<uint8_t> secret_;
  std::vector<uint8_t> secret_key_e_;
  std::vector<uint8_t> secret_key_r_;
  std::vector<uint8_t> zz_;
  std::vector<Encryption> encryptions_;
  std::vector<Export> exports_;
};

HpkeTestVector::HpkeTestVector(FileTest *t) {
  // Match FileTest's naming scheme for duplicated attribute names.
  auto BuildAttrName = [](const std::string &name, int iter) -> std::string {
    return iter == 1 ? name : name + "/" + std::to_string(iter);
  };
  // Read the |key| attribute from |t| and convert it to an int.
  auto FileTestReadInt = [](FileTest *t, const std::string &key) -> int {
    std::string tmp;
    EXPECT_TRUE(t->GetAttribute(&tmp, key));
    return std::stoi(tmp);
  };

  // Ignore the instruction that precedes an HPKE test vector.
  t->IgnoreInstruction("test");

  mode_ = FileTestReadInt(t, "mode");
  kem_id_ = FileTestReadInt(t, "kemID");
  kdf_id_ = FileTestReadInt(t, "kdfID");
  aead_id_ = FileTestReadInt(t, "aeadID");

  EXPECT_TRUE(t->GetBytes(&info_, "info"));

  std::vector<uint8_t> seed_r;
  EXPECT_TRUE(t->GetBytes(&seed_r, "seedR"));
  EXPECT_TRUE(DeriveX25519Keypair(EVP_sha256(), &secret_key_r_, &public_key_r_,
                                  seed_r));

  std::vector<uint8_t> seed_e;
  EXPECT_TRUE(t->GetBytes(&seed_e, "seedE"));
  std::vector<uint8_t> public_key_e_ignored;
  EXPECT_TRUE(DeriveX25519Keypair(EVP_sha256(), &secret_key_e_,
                                  &public_key_e_ignored, seed_e));

  EXPECT_TRUE(t->GetBytes(&enc_, "enc"));
  EXPECT_TRUE(t->GetBytes(&zz_, "zz"));
  EXPECT_TRUE(t->GetBytes(&context_, "keyScheduleContext"));
  EXPECT_TRUE(t->GetBytes(&secret_, "secret"));
  EXPECT_TRUE(t->GetBytes(&key_, "key"));
  EXPECT_TRUE(t->GetBytes(&nonce_, "outer_nonce"));
  EXPECT_TRUE(t->GetBytes(&exporter_secret_, "exporterSecret"));

  for (int i = 1; t->HasAttribute(BuildAttrName("aad", i)); i++) {
    HpkeTestVector::Encryption encryption;
    EXPECT_TRUE(t->GetBytes(&encryption.aad, BuildAttrName("aad", i)));
    EXPECT_TRUE(
        t->GetBytes(&encryption.ciphertext, BuildAttrName("ciphertext", i)));
    EXPECT_TRUE(t->GetBytes(&encryption.nonce, BuildAttrName("nonce", i)));
    EXPECT_TRUE(
        t->GetBytes(&encryption.plaintext, BuildAttrName("plaintext", i)));
    encryptions_.push_back(std::move(encryption));
  }

  for (int i = 1; t->HasAttribute(BuildAttrName("exportContext", i)); i++) {
    Export exp;
    EXPECT_TRUE(
        t->GetBytes(&exp.exportContext, BuildAttrName("exportContext", i)));
    exp.exportLength = FileTestReadInt(t, BuildAttrName("exportLength", i));
    EXPECT_TRUE(t->GetBytes(&exp.exportValue, BuildAttrName("exportValue", i)));
    exports_.push_back(std::move(exp));
  }
}

}  // namespace

TEST(HPKETest, ReadFileTest) {
  FileTestGTest("crypto/hpke/hpke_test_vectors.txt", [](FileTest *t) {
    HpkeTestVector test_vec(t);
    test_vec.Verify();
  });
}
