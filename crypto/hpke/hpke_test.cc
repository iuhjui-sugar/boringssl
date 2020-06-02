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
#include "third_party/openssl/boringssl/src/ssl/internal.h"
#include "third_party/openssl/curve25519.h"

// Test vectors from
// https://www.ietf.org/id/draft-irtf-cfrg-hpke-04.html#name-test-vectors

/*
  A.1. DHKEM(Curve25519, HKDF-SHA256), HKDF-SHA256, AES-GCM-128
  A.1.1. Base Setup Information
  mode: 0
  kemID: 32
  kdfID: 1
  aeadID: 1
  info: 4f6465206f6e2061204772656369616e2055726e
  skR: d3c8ca6516cd4cc75f66210c5a49d05381bfbfc0de090c19432d778ea4599829
  skE: b9d453d3ec0dbe59fa4a193bde3e4ea17f80c9b2fa69f2f3e029120303b86885
  pkR: 10b2fc2332b75206d2c791c3db1094dfd298b6508138ce98fec2c0c7a4dbc408
  pkE: 07da186c37d11e92d924fd1a75aff87d11860dfd59ea940429d8b874de846a33
  enc: 07da186c37d11e92d924fd1a75aff87d11860dfd59ea940429d8b874de846a33
  zz: 79f0c71200a133c4e608a1d2dab5830e54ba7ee71abd6522cfc4af6ad1c47ac2
  context: 002000010001005d0f5548cb13d7eba5320ae0e21b1ee274aac7ea1cce02570
  cf993d1b24564499e3cec2bd4e7128a963d96f013c353992d27115c0a2ab771af17d02c2
  528ef3c
  secret: e7a85117b9cac58c508eeb153faab0a8205a73d4fca1bb7b81d1a4b504eb71f8
  key: ab86480a0094bfe110fca55d98dccafd
  nonce: 4a5fc401e6551f69db44d64d
  exporterSecret:
  eb9570b621c3894a182c40ee67ed9d71bcfb114e2315b2ceaaade6454fa21291
  A.1.1.1. Encryptions
  sequence number: 0
  plaintext: 4265617574792069732074727574682c20747275746820626561757479
  aad: 436f756e742d30
  nonce: 4a5fc401e6551f69db44d64d
  ciphertext: 1ae0fe213b0c230f723d057a9476a5e95e9348699aec1ecfe67bd67a69cb
  63894b5aed52332059289c44c4a69e

  sequence number: 1
  plaintext: 4265617574792069732074727574682c20747275746820626561757479
  aad: 436f756e742d31
  nonce: 4a5fc401e6551f69db44d64c
  ciphertext: 00e8cec1e413913e942a214fd0d610fdcbe53285491d4e7bbfff51c11b40
  1c9e150cac56757e074d923d0de840

  sequence number: 2
  plaintext: 4265617574792069732074727574682c20747275746820626561757479
  aad: 436f756e742d32
  nonce: 4a5fc401e6551f69db44d64f
  ciphertext: 244862294f4036de67304d9f24da1079f4f914c8ffc768999065c657dda4
  0c0572c0d04e70d72cf3d150e4bf74

  sequence number: 4
  plaintext: 4265617574792069732074727574682c20747275746820626561757479
  aad: 436f756e742d34
  nonce: 4a5fc401e6551f69db44d649
  ciphertext: 4acf4661c93dc673a6d6372167f2a356c13e430e61a84ebc1919bf26dbc7
  d0132c7a54f9698094ddae52ac8e8f
*/

#define HPKE_CONTEXT_LEN (2 * X25519_PUBLIC_VALUE_LEN)

struct HpkeTestVector {
  uint8_t mode;
  uint16_t kem_id, kdf_id, aead_id;
  std::vector<uint8_t> info;
  std::vector<uint8_t> secret_key_r;
  std::vector<uint8_t> secret_key_e;
  std::vector<uint8_t> public_key_r;
  std::vector<uint8_t> public_key_e;
  std::vector<uint8_t> enc;
  std::vector<uint8_t> zz;
  std::vector<uint8_t> context;
  std::vector<uint8_t> secret;
  std::vector<uint8_t> key;
  std::vector<uint8_t> nonce;
  std::vector<uint8_t> exporter_secret;
};

/*

  skR: d3c8ca6516cd4cc75f66210c5a49d05381bfbfc0de090c19432d778ea4599829
  skE: b9d453d3ec0dbe59fa4a193bde3e4ea17f80c9b2fa69f2f3e029120303b86885
  pkR: 10b2fc2332b75206d2c791c3db1094dfd298b6508138ce98fec2c0c7a4dbc408
  pkE: 07da186c37d11e92d924fd1a75aff87d11860dfd59ea940429d8b874de846a33
  enc: 07da186c37d11e92d924fd1a75aff87d11860dfd59ea940429d8b874de846a33
  zz: 79f0c71200a133c4e608a1d2dab5830e54ba7ee71abd6522cfc4af6ad1c47ac2
  context: 002000010001005d0f5548cb13d7eba5320ae0e21b1ee274aac7ea1cce02570
  cf993d1b24564499e3cec2bd4e7128a963d96f013c353992d27115c0a2ab771af17d02c2
  528ef3c
  secret: e7a85117b9cac58c508eeb153faab0a8205a73d4fca1bb7b81d1a4b504eb71f8
  key: ab86480a0094bfe110fca55d98dccafd
  nonce: 4a5fc401e6551f69db44d64d
  exporterSecret:
  eb9570b621c3894a182c40ee67ed9d71bcfb114e2315b2ceaaade6454fa21291
*/

uint8_t ParseHexNibble(char nibble) {
  if ('0' <= nibble && nibble <= '9') {
    return nibble - '0';
  }
  if ('a' <= nibble && nibble <= 'f') {
    return nibble - 'a';
  }
  CHECK(false);
}

// Parse big-endian hexadecimal string |hex|.
std::vector<uint8_t> ParseHex(std::string hex) {
  CHECK_EQ(hex.size() % 2, 0);
  std::vector<uint8_t> bytes;
  for (int i = 0; i < hex.size(); i += 2) {
    uint8_t nibble_left = ParseHexNibble(hex[i]);
    uint8_t nibble_right = ParseHexNibble(hex[i + 1]);
    uint8_t byte_val = nibble_left * 16 + nibble_right;
    bytes.push_back(byte_val);
  }
  return bytes;
}

const HpkeTestVector kTestVectorBaseSetup{
    0 /* mode */,
    32 /*kem_id */,
    1 /* kdf_id */,
    1 /* aead_id */,
    ParseHex("4f6465206f6e2061204772656369616e2055726e") /* info */,
    ParseHex("d3c8ca6516cd4cc75f66210c5a49d05381bfbfc0de090c19432d778ea4599"
             "829") /* secret_key_r */,
    ParseHex("b9d453d3ec0dbe59fa4a193bde3e4ea17f80c9b2fa69f2f3e029120303b86"
             "885") /* secret_key_e */,
    ParseHex("10b2fc2332b75206d2c791c3db1094dfd298b6508138ce98fec2c0c7a4dbc"
             "408") /* public_key_r */,
    ParseHex("07da186c37d11e92d924fd1a75aff87d11860dfd59ea940429d8b874de846"
             "a33") /* public_key_e */,
    ParseHex("07da186c37d11e92d924fd1a75aff87d11860dfd59ea940429d8b874de846"
             "a33") /* enc */,
    ParseHex("79f0c71200a133c4e608a1d2dab5830e54ba7ee71abd6522cfc4af6ad1c47"
             "ac2") /* zz */,
    ParseHex("002000010001005d0f5548cb13d7eba5320ae0e21b1ee274aac7ea1cce025"
             "70cf993d1b24564499e3cec2bd4e7128a963d96f013c353992d27115c0a2a"
             "b771af17d02c2528ef3c") /* context */,
    ParseHex("e7a85117b9cac58c508eeb153faab0a8205a73d4fca1bb7b81d1a4b504eb7"
             "1f8") /* secret */,
    ParseHex("ab86480a0094bfe110fca55d98dccafd") /* key */,
    ParseHex("4a5fc401e6551f69db44d64d") /* nonce */,
    ParseHex("eb9570b621c3894a182c40ee67ed9d71bcfb114e2315b2ceaaade6454fa21"
             "291") /* exporter_secret */,
};

TEST(HPKETest, Trivial) {
  EVP_HPKE_CTX ctx;
  EVP_HPKE_CTX_init(&ctx);
  EVP_HPKE_CTX_cleanup(&ctx);
}

// Calls SetupBaseS and SetupBaseR functions, but does not check the outputs.
TEST(HPKETest, TrivialSetupBase) {
  uint8_t enc[X25519_PUBLIC_VALUE_LEN];
  {
    EVP_HPKE_CTX sender_ctx;
    EVP_HPKE_CTX_init(&sender_ctx);

    uint8_t public_key[X25519_PUBLIC_VALUE_LEN];
    uint8_t private_key[X25519_PRIVATE_KEY_LEN];
    X25519_keypair(public_key, private_key);

    EXPECT_TRUE(EVP_HPKE_CTX_setup_base_x25519_s(&sender_ctx, enc, public_key,
                                                 NULL, 0));
    EVP_HPKE_CTX_cleanup(&sender_ctx);
  }
  {
    EVP_HPKE_CTX receiver_ctx;
    EVP_HPKE_CTX_init(&receiver_ctx);

    uint8_t public_key[X25519_PUBLIC_VALUE_LEN];
    uint8_t private_key[X25519_PRIVATE_KEY_LEN];
    X25519_keypair(public_key, private_key);

    EXPECT_TRUE(EVP_HPKE_CTX_setup_base_x25519_r(&receiver_ctx, enc,
                                                 private_key, NULL, 0));
    EVP_HPKE_CTX_cleanup(&receiver_ctx);
  }
}

void hpke_ephemeral_keypair_set(EVP_HPKE_CTX *hpke,
                                const uint8_t priv[X25519_PRIVATE_KEY_LEN]) {
  OPENSSL_memcpy(hpke->secret_key_ephemeral, priv, X25519_PRIVATE_KEY_LEN);
  hpke->secret_key_ephemeral_len = X25519_PRIVATE_KEY_LEN;
}

TEST(HPKETest, TestVectors) {
  EVP_HPKE_CTX sender_ctx;
  EVP_HPKE_CTX_init(&sender_ctx);
  uint8_t enc[X25519_PUBLIC_VALUE_LEN];
  EXPECT_TRUE(EVP_HPKE_CTX_setup_base_x25519_s(
      &sender_ctx, enc, kTestVectorBaseSetup.public_key_r.data(),
      kTestVectorBaseSetup.info.data(), kTestVectorBaseSetup.info.size()));

  hpke_ephemeral_keypair_set(&sender_ctx,
                             kTestVectorBaseSetup.secret_key_e.data());

  // Verify that |enc| matches test vector.
  EXPECT_EQ(bssl::Span<const uint8_t>(enc, sizeof(enc)),
            bssl::Span<const uint8_t>(kTestVectorBaseSetup.enc.data(),
                                      kTestVectorBaseSetup.enc.size()));

  EVP_HPKE_CTX receiver_ctx;
  EVP_HPKE_CTX_init(&receiver_ctx);
}
