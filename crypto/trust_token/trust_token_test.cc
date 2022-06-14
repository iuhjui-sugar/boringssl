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

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <algorithm>
#include <limits>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/trust_token.h>

#include "../ec_extra/internal.h"
#include "../fipsmodule/ec/internal.h"
#include "../internal.h"
#include "../test/test_util.h"
#include "internal.h"


BSSL_NAMESPACE_BEGIN

namespace {

TEST(TrustTokenTest, KeyGenExp1) {
  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len;
  ASSERT_TRUE(TRUST_TOKEN_generate_key(
      TRUST_TOKEN_experiment_v1(), priv_key, &priv_key_len,
      TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key, &pub_key_len,
      TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0x0001));
  ASSERT_EQ(292u, priv_key_len);
  ASSERT_EQ(301u, pub_key_len);

  const uint8_t kKeygenSeed[] = "SEED";
  ASSERT_TRUE(TRUST_TOKEN_generate_fixed_key(
      TRUST_TOKEN_experiment_v1(), priv_key, &priv_key_len,
      TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key, &pub_key_len,
      TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0x0001, kKeygenSeed,
      sizeof(kKeygenSeed) - 1));

  const uint8_t kExpectedPriv[] =
      "\x00\x00\x00\x01\xfe\x12\xbd\x23\x5d\x79\x8d\xa3\xc9\xcb\x3d\xb6\xca"
      "\x88\xf7\xe3\x93\x95\xaa\x0e\x1c\xa8\x7d\x06\xac\x78\x33\x02\x0c\xed"
      "\xd6\x94\x69\x99\x18\x9b\x6e\x7f\xd0\xe1\xb2\x69\xe4\xca\xcc\x3c\x2d"
      "\x07\xc5\x17\x87\x8f\x67\x0b\xca\xd6\x0b\x10\x7c\x31\x34\x99\x70\xcf"
      "\xcd\x5c\xf5\x76\xdd\x5f\x99\xdb\x62\x02\x0a\xf9\x91\xb5\x9d\x0a\x9c"
      "\xf5\x3b\x02\x71\xcb\x1b\x57\x13\x3a\xb6\x70\x3d\x22\x83\x20\x45\x93"
      "\x9a\x04\x50\x2a\x21\x22\x4f\xbc\xda\x51\xa0\x70\x3e\x2c\xbc\x41\x99"
      "\x28\x13\x2b\xf9\x45\x51\x3e\xaf\x86\x18\xef\xed\xd4\xcd\x31\x9b\xbe"
      "\x67\xfe\x87\x39\x86\x1a\x05\xed\x66\x45\x0e\xdc\xc5\x17\x87\x8f\x67"
      "\x0b\xca\xd6\x0b\x10\x7c\x31\x34\x99\x70\xcf\xcd\x5c\xf5\x76\xdd\x5f"
      "\x99\xdb\x62\x02\x0a\xf9\x91\xb5\x9d\x0a\x9c\xf5\x3b\x02\x71\xcb\x1b"
      "\x57\x13\x3a\xb6\x70\x3d\x22\x83\x20\x2b\xf3\x21\x3c\x2b\xac\x4d\x51"
      "\x74\xfa\xdc\x77\x16\x22\x68\x99\x5b\xec\xb6\xdb\x88\x2c\x02\x8f\xd2"
      "\x27\x5f\x9b\x10\xbf\x9b\xf1\x0f\x9c\xb6\xab\x7f\x8c\x33\xee\x66\x7b"
      "\x5b\x9c\x09\x21\x4e\x4e\xc5\x17\x87\x8f\x67\x0b\xca\xd6\x0b\x10\x7c"
      "\x31\x34\x99\x70\xcf\xcd\x5c\xf5\x76\xdd\x5f\x99\xdb\x62\x02\x0a\xf9"
      "\x91\xb5\x9d\x0a\x9c\xf5\x3b\x02\x71\xcb\x1b\x57\x13\x3a\xb6\x70\x3d"
      "\x22\x83\x20";
  ASSERT_EQ(Bytes(kExpectedPriv, sizeof(kExpectedPriv) - 1),
            Bytes(priv_key, priv_key_len));

  const uint8_t kExpectedPub[] =
      "\x00\x00\x00\x01\x00\x61\x04\x5a\xfa\xac\xbb\xae\x58\x50\x36\x14\x71"
      "\xd3\xc0\x05\x59\x11\x2d\x11\xdd\x38\x8b\x2c\xfc\x32\x88\xe7\x9d\xdd"
      "\xea\x33\xab\x16\x25\x8f\x4f\x5b\xaa\x68\x02\xa8\x03\xc5\xf2\x34\x39"
      "\x11\x9d\xc0\xe8\x7e\xc3\xe8\xf3\x26\x46\x4d\x06\xd3\x29\xf1\x12\x5e"
      "\xdf\x1b\x57\xe9\xf0\xaa\xa1\x58\x43\x8a\x71\xca\xee\x1e\x2f\x37\xf5"
      "\x5a\xc8\x1f\x91\x53\xd9\xe2\x4c\x13\xb5\xe2\xc7\x24\x27\xe4\xc4\xaa"
      "\xa5\x00\x61\x04\x1a\x29\x51\xa5\x57\x63\x26\x06\xb1\xdc\x13\x46\xfa"
      "\x2b\xec\x81\xbb\x04\x64\xb6\x4a\xd3\x79\xc5\xd1\x7f\xd1\x70\xf4\x67"
      "\x90\xec\xc7\x29\xc2\xd5\xb6\x69\x33\x1c\x08\x90\x09\xf8\xa6\x27\x29"
      "\xe3\x82\xf8\xaf\x9a\x0f\x42\xb2\x15\x75\x9a\x75\x83\xa3\x8c\x02\x0d"
      "\xad\x66\xc6\x76\x6c\x2a\x38\xf6\x90\x8c\x9a\x3b\x8d\xac\x77\x26\xd6"
      "\xbd\x6e\xee\x10\x45\x9c\x33\xd1\xad\x24\xf3\x32\x9c\x69\xc7\x00\x61"
      "\x04\x78\xab\xca\x51\xe8\x7d\xe1\xef\xdd\xe8\x07\x3a\x6f\xc8\x8f\xa0"
      "\x97\xc0\x00\x7c\x60\xd9\xfe\x9c\x47\x29\x72\x7b\x10\x59\xd8\xd7\x33"
      "\xb5\xc2\x17\xce\xbb\x1a\x1b\xde\x90\x1f\x50\xa5\xe4\x29\xf8\xf6\x32"
      "\x2d\xcd\xc0\x2e\x59\xaa\x2d\x56\x21\x2f\x3c\xec\x9f\x4e\x4c\x10\x83"
      "\xd0\xe7\x79\x63\xf5\x94\x12\xa6\xf6\x4f\x22\x69\xaa\x66\x4f\x04\x44"
      "\xe0\xa1\xa4\xfa\x3c\x85\x42\x97\xba\xcd\x82\x92";
  ASSERT_EQ(Bytes(kExpectedPub, sizeof(kExpectedPub) - 1),
            Bytes(pub_key, pub_key_len));
}

TEST(TrustTokenTest, KeyGenExp2VOPRF) {
  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len;
  ASSERT_TRUE(TRUST_TOKEN_generate_key(
      TRUST_TOKEN_experiment_v2_voprf(), priv_key, &priv_key_len,
      TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key, &pub_key_len,
      TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0x0001));
  ASSERT_EQ(52u, priv_key_len);
  ASSERT_EQ(101u, pub_key_len);

  const uint8_t kKeygenSeed[] = "SEED";
  ASSERT_TRUE(TRUST_TOKEN_generate_fixed_key(
      TRUST_TOKEN_experiment_v2_voprf(), priv_key, &priv_key_len,
      TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key, &pub_key_len,
      TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0x0001, kKeygenSeed,
      sizeof(kKeygenSeed) - 1));

  const uint8_t kExpectedPriv[] =
      "\x00\x00\x00\x01\x0b\xe2\xc4\x73\x92\xe7\xf8\x3e\xba\xab\x85\xa7\x77"
      "\xd7\x0a\x02\xc5\x36\xfe\x62\xa3\xca\x01\x75\xc7\x62\x19\xc7\xf0\x30"
      "\xc5\x14\x60\x13\x97\x4f\x63\x05\x37\x92\x7b\x76\x8e\x9f\xd0\x1a\x74"
      "\x44";
  ASSERT_EQ(Bytes(kExpectedPriv, sizeof(kExpectedPriv) - 1),
            Bytes(priv_key, priv_key_len));

  const uint8_t kExpectedPub[] =
      "\x00\x00\x00\x01\x04\x2c\x9c\x11\xc1\xe5\x52\x59\x0b\x6d\x88\x8b\x6e"
      "\x28\xe8\xc5\xa3\xbe\x48\x18\xf7\x1d\x31\xcf\xa2\x6e\x2a\xd6\xcb\x83"
      "\x26\x04\xbd\x93\x67\xe4\x53\xf6\x11\x7d\x45\xe9\xfe\x27\x33\x90\xdb"
      "\x1b\xfc\x9b\x31\x4d\x39\x1f\x1f\x8c\x43\x06\x70\x2c\x84\xdc\x23\x18"
      "\xc7\x6a\x58\xcf\x9e\xc1\xfa\xf2\x30\xdd\xad\x62\x24\xde\x11\xc1\xba"
      "\x8d\xc3\x4f\xfb\xe5\xa5\xd4\x37\xba\x3b\x70\xc0\xc3\xef\x20\x43";
  ASSERT_EQ(Bytes(kExpectedPub, sizeof(kExpectedPub) - 1),
            Bytes(pub_key, pub_key_len));
}

TEST(TrustTokenTest, KeyGenExp2PMB) {
  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len;
  ASSERT_TRUE(TRUST_TOKEN_generate_key(
      TRUST_TOKEN_experiment_v2_pmb(), priv_key, &priv_key_len,
      TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key, &pub_key_len,
      TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0x0001));
  ASSERT_EQ(292u, priv_key_len);
  ASSERT_EQ(295u, pub_key_len);

  const uint8_t kKeygenSeed[] = "SEED";
  ASSERT_TRUE(TRUST_TOKEN_generate_fixed_key(
      TRUST_TOKEN_experiment_v2_pmb(), priv_key, &priv_key_len,
      TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key, &pub_key_len,
      TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0x0001, kKeygenSeed,
      sizeof(kKeygenSeed) - 1));

  const uint8_t kExpectedPriv[] =
      "\x00\x00\x00\x01\x14\xba\x88\x94\xf0\x72\xf1\xc0\x5c\x07\x15\x7b\x9c"
      "\x73\x4a\x8e\xa0\x7b\x5c\x21\x8c\xba\xa3\xa5\x87\x79\x25\x30\x37\x22"
      "\xa0\x6a\x31\x8c\xb2\xba\xa1\x03\x7e\xae\x0f\x83\xc9\xc7\x80\xdc\x55"
      "\xd4\x31\x38\xd9\x2f\x0e\x0a\xde\x93\xaf\x9d\x63\x67\x5e\xe6\xf3\xe1"
      "\x20\xec\x78\x71\xca\x80\x74\xda\x0b\xb3\x97\xd2\xd8\xb1\x03\x56\xe4"
      "\x7a\x94\xe9\xf0\x15\x49\x46\x6c\x72\x50\x74\xfe\xa2\xdf\x4c\xb4\x5b"
      "\xe0\x3c\x83\x18\xd8\xd5\xa5\x2d\x3f\x2c\xf2\x67\xe0\x8a\xdf\x0a\x36"
      "\x4f\xfb\x95\x4a\xd8\x5b\x39\xb0\xc2\xf9\xe6\xbb\x1a\xf7\x3a\x4a\x23"
      "\x0f\xd7\xec\x2a\xb2\xc1\xcb\x08\xda\xa1\x61\x73\x31\x38\xd9\x2f\x0e"
      "\x0a\xde\x93\xaf\x9d\x63\x67\x5e\xe6\xf3\xe1\x20\xec\x78\x71\xca\x80"
      "\x74\xda\x0b\xb3\x97\xd2\xd8\xb1\x03\x56\xe4\x7a\x94\xe9\xf0\x15\x49"
      "\x46\x6c\x72\x50\x74\xfe\xa2\xdf\x4c\x6a\xb9\xac\xf7\xc5\x74\x3b\x9e"
      "\xbc\x04\x17\xfa\x4e\x3a\xc9\x25\x18\x23\xe6\x9c\xf3\x17\x1a\xa0\x69"
      "\xd2\xb2\xb7\x28\x0b\xff\x5e\x5b\x29\xb6\x50\xd9\x86\x0d\x49\xa5\x73"
      "\x32\x6e\x35\xd7\xfb\x31\x31\x38\xd9\x2f\x0e\x0a\xde\x93\xaf\x9d\x63"
      "\x67\x5e\xe6\xf3\xe1\x20\xec\x78\x71\xca\x80\x74\xda\x0b\xb3\x97\xd2"
      "\xd8\xb1\x03\x56\xe4\x7a\x94\xe9\xf0\x15\x49\x46\x6c\x72\x50\x74\xfe"
      "\xa2\xdf\x4c";
  ASSERT_EQ(Bytes(kExpectedPriv, sizeof(kExpectedPriv) - 1),
            Bytes(priv_key, priv_key_len));

  const uint8_t kExpectedPub[] =
      "\x00\x00\x00\x01\x04\x45\xe7\x1e\xf0\x88\xc9\x5b\x1b\x82\x14\xda\xa5"
      "\x28\xec\x95\x10\xc7\x05\x3c\x09\x68\xf0\x19\x53\xf7\xd2\x8c\xc2\x79"
      "\xe3\xf8\x80\x58\x63\x2d\xdc\x1c\xc8\xe4\x90\x08\x4f\x57\x38\x71\xff"
      "\xac\xb5\x79\x0b\x0b\x73\x9d\x80\x86\xc3\x57\x79\xd3\x9d\x2c\xa4\x4d"
      "\xa9\x38\x75\xb4\xd4\x48\x0c\xd0\x1b\x1d\x66\xba\xc2\x72\xf3\x9a\x10"
      "\x01\xb4\x86\x23\xda\x15\x30\x1c\x0e\x7f\x57\xa0\x38\xdc\x67\xe0\x04"
      "\xd1\xe7\x2d\xe7\x2c\xcd\x20\x93\x92\x95\x66\xf9\xd7\xb5\xc4\xb6\x39"
      "\x8a\xcb\x9d\x1b\xcd\xdb\x1e\x04\x73\xaa\x09\x39\xae\xe3\x65\x19\x6c"
      "\x2e\x4a\x7a\x16\x67\x82\x2d\x2a\x92\x17\xe1\xda\x8a\x3c\x82\x3f\xe2"
      "\x23\xae\x88\x0a\x2a\x33\x36\xf6\xc2\xd4\x6e\xb5\x3f\xe6\xe1\xc8\xc9"
      "\x23\x22\x30\x27\xb5\x44\xab\x48\x2e\xad\x71\xdf\x25\xde\x52\x05\xf1"
      "\x24\x45\x0f\x26\x81\xa2\x1a\x08\xa1\xdf\xb6\x04\x82\x59\xfb\x50\x7c"
      "\x88\x2e\x5a\xfb\xbb\xec\xd1\x91\x66\xe6\x3e\x6f\x6e\xec\x0c\xc3\x02"
      "\x4a\xa2\x3b\xff\x30\x0c\x9b\x77\x13\xe5\x46\x16\xa3\x11\x72\x04\x7c"
      "\xa7\x65\x70\x31\xa3\x19\xa2\x7e\xd7\x6b\x28\x07\xf4\x8f\x93\xc5\x17"
      "\x83\x5c\xc1\x19\x25\xfe\x21\xda\x8e\xce\xeb\x1a\x90\xc9\xf5\x94\x3a"
      "\xb9\x67\x7f\x28\x40\x70\xe7\x58\xe7\x7d\xf5\x16\xff\x0e\x49\x12\x7b"
      "\x41\x72\x3e\xcb\x50\xe1";
  ASSERT_EQ(Bytes(kExpectedPub, sizeof(kExpectedPub) - 1),
            Bytes(pub_key, pub_key_len));
}

// Test that H in |TRUST_TOKEN_experiment_v1| was computed correctly.
TEST(TrustTokenTest, HExp1) {
  const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
  ASSERT_TRUE(group);

  const uint8_t kHGen[] = "generator";
  const uint8_t kHLabel[] = "PMBTokens Experiment V1 HashH";

  bssl::UniquePtr<EC_POINT> expected_h(EC_POINT_new(group));
  ASSERT_TRUE(expected_h);
  ASSERT_TRUE(ec_hash_to_curve_p384_xmd_sha512_sswu_draft07(
      group, &expected_h->raw, kHLabel, sizeof(kHLabel), kHGen, sizeof(kHGen)));
  uint8_t expected_bytes[1 + 2 * EC_MAX_BYTES];
  size_t expected_len =
      EC_POINT_point2oct(group, expected_h.get(), POINT_CONVERSION_UNCOMPRESSED,
                         expected_bytes, sizeof(expected_bytes), nullptr);

  uint8_t h[97];
  ASSERT_TRUE(pmbtoken_exp1_get_h_for_testing(h));
  EXPECT_EQ(Bytes(h), Bytes(expected_bytes, expected_len));
}

// Test that H in |TRUST_TOKEN_experiment_v2_pmb| was computed correctly.
TEST(TrustTokenTest, HExp2) {
  const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
  ASSERT_TRUE(group);

  const uint8_t kHGen[] = "generator";
  const uint8_t kHLabel[] = "PMBTokens Experiment V2 HashH";

  bssl::UniquePtr<EC_POINT> expected_h(EC_POINT_new(group));
  ASSERT_TRUE(expected_h);
  ASSERT_TRUE(ec_hash_to_curve_p384_xmd_sha512_sswu_draft07(
      group, &expected_h->raw, kHLabel, sizeof(kHLabel), kHGen, sizeof(kHGen)));
  uint8_t expected_bytes[1 + 2 * EC_MAX_BYTES];
  size_t expected_len =
      EC_POINT_point2oct(group, expected_h.get(), POINT_CONVERSION_UNCOMPRESSED,
                         expected_bytes, sizeof(expected_bytes), nullptr);

  uint8_t h[97];
  ASSERT_TRUE(pmbtoken_exp2_get_h_for_testing(h));
  EXPECT_EQ(Bytes(h), Bytes(expected_bytes, expected_len));
}

static std::vector<const TRUST_TOKEN_METHOD *> AllMethods() {
  return {
    TRUST_TOKEN_experiment_v1(),
    TRUST_TOKEN_experiment_v2_voprf(),
    TRUST_TOKEN_experiment_v2_pmb()
  };
}

class TrustTokenProtocolTestBase : public ::testing::Test {
 public:
  explicit TrustTokenProtocolTestBase(const TRUST_TOKEN_METHOD *method_arg)
      : method_(method_arg) {}

  // KeyID returns the key ID associated with key index |i|.
  static uint32_t KeyID(size_t i) {
    // Use a different value from the indices to that we do not mix them up.
    return 7 + i;
  }

  const TRUST_TOKEN_METHOD *method() { return method_; }

 protected:
  void SetupContexts() {
    client.reset(TRUST_TOKEN_CLIENT_new(method(), client_max_batchsize));
    ASSERT_TRUE(client);
    issuer.reset(TRUST_TOKEN_ISSUER_new(method(), issuer_max_batchsize));
    ASSERT_TRUE(issuer);

    for (size_t i = 0; i < method()->max_keys; i++) {
      uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
      uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
      size_t priv_key_len, pub_key_len, key_index;
      ASSERT_TRUE(TRUST_TOKEN_generate_key(
          method(), priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
          pub_key, &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, KeyID(i)));
      ASSERT_TRUE(TRUST_TOKEN_CLIENT_add_key(client.get(), &key_index, pub_key,
                                             pub_key_len));
      ASSERT_EQ(i, key_index);
      ASSERT_TRUE(
          TRUST_TOKEN_ISSUER_add_key(issuer.get(), priv_key, priv_key_len));
    }

    uint8_t public_key[32], private_key[64];
    ED25519_keypair(public_key, private_key);
    bssl::UniquePtr<EVP_PKEY> priv(EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, private_key, 32));
    ASSERT_TRUE(priv);
    bssl::UniquePtr<EVP_PKEY> pub(
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key, 32));
    ASSERT_TRUE(pub);

    TRUST_TOKEN_CLIENT_set_srr_key(client.get(), pub.get());
    TRUST_TOKEN_ISSUER_set_srr_key(issuer.get(), priv.get());
    RAND_bytes(metadata_key, sizeof(metadata_key));
    ASSERT_TRUE(TRUST_TOKEN_ISSUER_set_metadata_key(issuer.get(), metadata_key,
                                                    sizeof(metadata_key)));
  }

  const TRUST_TOKEN_METHOD *method_;
  uint16_t client_max_batchsize = 10;
  uint16_t issuer_max_batchsize = 10;
  bssl::UniquePtr<TRUST_TOKEN_CLIENT> client;
  bssl::UniquePtr<TRUST_TOKEN_ISSUER> issuer;
  uint8_t metadata_key[32];
};

class TrustTokenProtocolTest
    : public TrustTokenProtocolTestBase,
      public testing::WithParamInterface<const TRUST_TOKEN_METHOD *> {
 public:
  TrustTokenProtocolTest() : TrustTokenProtocolTestBase(GetParam()) {}
};

INSTANTIATE_TEST_SUITE_P(TrustTokenAllProtocolTest, TrustTokenProtocolTest,
                         testing::ValuesIn(AllMethods()));

TEST_P(TrustTokenProtocolTest, InvalidToken) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;

  size_t key_index;
  size_t tokens_issued;
  ASSERT_TRUE(
      TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg, &msg_len, 1));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/KeyID(0), /*private_metadata=*/0,
      /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);

  for (TRUST_TOKEN *token : tokens.get()) {
    // Corrupt the token.
    token->data[0] ^= 0x42;

    uint8_t *redeem_msg = NULL, *redeem_resp = NULL;
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_redemption(
        client.get(), &redeem_msg, &msg_len, token, NULL, 0, 0));
    bssl::UniquePtr<uint8_t> free_redeem_msg(redeem_msg);
    TRUST_TOKEN *rtoken;
    uint8_t *client_data;
    size_t client_data_len;
    uint64_t redemption_time;
    ASSERT_FALSE(TRUST_TOKEN_ISSUER_redeem(
        issuer.get(), &redeem_resp, &resp_len, &rtoken, &client_data,
        &client_data_len, &redemption_time, redeem_msg, msg_len, 600));
    bssl::UniquePtr<uint8_t> free_redeem_resp(redeem_resp);
  }
}

TEST_P(TrustTokenProtocolTest, TruncatedIssuanceRequest) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  msg_len = 10;
  size_t tokens_issued;
  ASSERT_FALSE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/KeyID(0), /*private_metadata=*/0,
      /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
}

TEST_P(TrustTokenProtocolTest, TruncatedIssuanceResponse) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/KeyID(0), /*private_metadata=*/0,
      /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  resp_len = 10;
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_FALSE(tokens);
}

TEST_P(TrustTokenProtocolTest, ExtraDataIssuanceResponse) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *request = NULL, *response = NULL;
  size_t request_len, response_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &request,
                                                &request_len, 10));
  bssl::UniquePtr<uint8_t> free_request(request);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(issuer.get(), &response, &response_len,
                                       &tokens_issued, request, request_len,
                                       /*public_metadata=*/KeyID(0),
                                       /*private_metadata=*/0,
                                       /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_response(response);
  std::vector<uint8_t> response2(response, response + response_len);
  response2.push_back(0);
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index,
                                         response2.data(), response2.size()));
  ASSERT_FALSE(tokens);
}

TEST_P(TrustTokenProtocolTest, TruncatedRedemptionRequest) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/KeyID(0), /*private_metadata=*/0,
      /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);

  for (TRUST_TOKEN *token : tokens.get()) {
    const uint8_t kClientData[] = "\x70TEST CLIENT DATA";
    uint64_t kRedemptionTime = (method()->has_srr ? 13374242 : 0);

    uint8_t *redeem_msg = NULL, *redeem_resp = NULL;
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_redemption(
        client.get(), &redeem_msg, &msg_len, token, kClientData,
        sizeof(kClientData) - 1, kRedemptionTime));
    bssl::UniquePtr<uint8_t> free_redeem_msg(redeem_msg);
    msg_len = 10;

    TRUST_TOKEN *rtoken;
    uint8_t *client_data;
    size_t client_data_len;
    uint64_t redemption_time;
    ASSERT_FALSE(TRUST_TOKEN_ISSUER_redeem(
        issuer.get(), &redeem_resp, &resp_len, &rtoken, &client_data,
        &client_data_len, &redemption_time, redeem_msg, msg_len, 600));
  }
}

TEST_P(TrustTokenProtocolTest, TruncatedRedemptionResponse) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/KeyID(0), /*private_metadata=*/0,
      /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);

  for (TRUST_TOKEN *token : tokens.get()) {
    const uint8_t kClientData[] = "\x70TEST CLIENT DATA";
    uint64_t kRedemptionTime = 0;

    uint8_t *redeem_msg = NULL, *redeem_resp = NULL;
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_redemption(
        client.get(), &redeem_msg, &msg_len, token, kClientData,
        sizeof(kClientData) - 1, kRedemptionTime));
    bssl::UniquePtr<uint8_t> free_redeem_msg(redeem_msg);
    TRUST_TOKEN *rtoken;
    uint8_t *client_data;
    size_t client_data_len;
    uint64_t redemption_time;
    ASSERT_TRUE(TRUST_TOKEN_ISSUER_redeem(
        issuer.get(), &redeem_resp, &resp_len, &rtoken, &client_data,
        &client_data_len, &redemption_time, redeem_msg, msg_len, 600));
    bssl::UniquePtr<uint8_t> free_redeem_resp(redeem_resp);
    bssl::UniquePtr<uint8_t> free_client_data(client_data);
    bssl::UniquePtr<TRUST_TOKEN> free_rtoken(rtoken);

    ASSERT_EQ(redemption_time, kRedemptionTime);
    ASSERT_EQ(Bytes(kClientData, sizeof(kClientData) - 1),
              Bytes(client_data, client_data_len));
    resp_len = 10;

    // If the protocol doesn't use SRRs, TRUST_TOKEN_CLIENT_finish_redemtpion
    // leaves all SRR validation to the caller.
    uint8_t *srr = NULL, *sig = NULL;
    size_t srr_len, sig_len;
    bool expect_failure = !method()->has_srr;
    ASSERT_EQ(expect_failure, TRUST_TOKEN_CLIENT_finish_redemption(
                                  client.get(), &srr, &srr_len, &sig, &sig_len,
                                  redeem_resp, resp_len));
    bssl::UniquePtr<uint8_t> free_srr(srr);
    bssl::UniquePtr<uint8_t> free_sig(sig);
  }
}

TEST_P(TrustTokenProtocolTest, IssuedWithBadKeyID) {
  client.reset(TRUST_TOKEN_CLIENT_new(method(), client_max_batchsize));
  ASSERT_TRUE(client);
  issuer.reset(TRUST_TOKEN_ISSUER_new(method(), issuer_max_batchsize));
  ASSERT_TRUE(issuer);

  // We configure the client and the issuer with different key IDs and test
  // that the client notices.
  const uint32_t kClientKeyID = 0;
  const uint32_t kIssuerKeyID = 42;

  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len, key_index;
  ASSERT_TRUE(TRUST_TOKEN_generate_key(
      method(), priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
      pub_key, &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, kClientKeyID));
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_add_key(client.get(), &key_index, pub_key,
                                         pub_key_len));
  ASSERT_EQ(0UL, key_index);

  ASSERT_TRUE(TRUST_TOKEN_generate_key(
      method(), priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
      pub_key, &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, kIssuerKeyID));
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_add_key(issuer.get(), priv_key, priv_key_len));


  uint8_t public_key[32], private_key[64];
  ED25519_keypair(public_key, private_key);
  bssl::UniquePtr<EVP_PKEY> priv(
      EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, private_key, 32));
  ASSERT_TRUE(priv);
  bssl::UniquePtr<EVP_PKEY> pub(
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key, 32));
  ASSERT_TRUE(pub);

  TRUST_TOKEN_CLIENT_set_srr_key(client.get(), pub.get());
  TRUST_TOKEN_ISSUER_set_srr_key(issuer.get(), priv.get());
  RAND_bytes(metadata_key, sizeof(metadata_key));
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_set_metadata_key(issuer.get(), metadata_key,
                                                  sizeof(metadata_key)));


  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/42, /*private_metadata=*/0, /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_FALSE(tokens);
}

class TrustTokenMetadataTest
    : public TrustTokenProtocolTestBase,
      public testing::WithParamInterface<
          std::tuple<const TRUST_TOKEN_METHOD *, int, bool>> {
 public:
  TrustTokenMetadataTest()
      : TrustTokenProtocolTestBase(std::get<0>(GetParam())) {}

  int public_metadata() { return std::get<1>(GetParam()); }
  bool private_metadata() { return std::get<2>(GetParam()); }
};

TEST_P(TrustTokenMetadataTest, SetAndGetMetadata) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  bool result = TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      public_metadata(), private_metadata(), /*max_issuance=*/1);
  if (!method()->has_private_metadata && private_metadata()) {
    ASSERT_FALSE(result);
    return;
  }
  ASSERT_TRUE(result);
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);

  for (TRUST_TOKEN *token : tokens.get()) {
    const uint8_t kClientData[] = "\x70TEST CLIENT DATA";
    uint64_t kRedemptionTime = (method()->has_srr ? 13374242 : 0);

    const uint8_t kExpectedSRRV1[] =
        "\xa4\x68\x6d\x65\x74\x61\x64\x61\x74\x61\xa2\x66\x70\x75\x62\x6c\x69"
        "\x63\x00\x67\x70\x72\x69\x76\x61\x74\x65\x00\x6a\x74\x6f\x6b\x65\x6e"
        "\x2d\x68\x61\x73\x68\x58\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x6b\x63\x6c\x69\x65\x6e\x74\x2d\x64\x61\x74\x61"
        "\x70\x54\x45\x53\x54\x20\x43\x4c\x49\x45\x4e\x54\x20\x44\x41\x54\x41"
        "\x70\x65\x78\x70\x69\x72\x79\x2d\x74\x69\x6d\x65\x73\x74\x61\x6d\x70"
        "\x1a\x00\xcc\x15\x7a";

    const uint8_t kExpectedSRRV2[] =
        "\xa4\x68\x6d\x65\x74\x61\x64\x61\x74\x61\xa2\x66\x70\x75\x62\x6c\x69"
        "\x63\x00\x67\x70\x72\x69\x76\x61\x74\x65\x00\x6a\x74\x6f\x6b\x65\x6e"
        "\x2d\x68\x61\x73\x68\x58\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x6b\x63\x6c\x69\x65\x6e\x74\x2d\x64\x61\x74\x61"
        "\x70\x54\x45\x53\x54\x20\x43\x4c\x49\x45\x4e\x54\x20\x44\x41\x54\x41"
        "\x70\x65\x78\x70\x69\x72\x79\x2d\x74\x69\x6d\x65\x73\x74\x61\x6d\x70"
        "\x00";

    const uint8_t *expected_srr = kExpectedSRRV1;
    size_t expected_srr_len = sizeof(kExpectedSRRV1) - 1;
    if (!method()->has_srr) {
      expected_srr = kExpectedSRRV2;
      expected_srr_len = sizeof(kExpectedSRRV2) - 1;
    }

    uint8_t *redeem_msg = NULL, *redeem_resp = NULL;
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_redemption(
        client.get(), &redeem_msg, &msg_len, token, kClientData,
        sizeof(kClientData) - 1, kRedemptionTime));
    bssl::UniquePtr<uint8_t> free_redeem_msg(redeem_msg);
    TRUST_TOKEN *rtoken;
    uint8_t *client_data;
    size_t client_data_len;
    uint64_t redemption_time;
    ASSERT_TRUE(TRUST_TOKEN_ISSUER_redeem(
        issuer.get(), &redeem_resp, &resp_len, &rtoken, &client_data,
        &client_data_len, &redemption_time, redeem_msg, msg_len, 600));
    bssl::UniquePtr<uint8_t> free_redeem_resp(redeem_resp);
    bssl::UniquePtr<uint8_t> free_client_data(client_data);
    bssl::UniquePtr<TRUST_TOKEN> free_rtoken(rtoken);

    ASSERT_EQ(redemption_time, kRedemptionTime);
    ASSERT_EQ(Bytes(kClientData, sizeof(kClientData) - 1),
              Bytes(client_data, client_data_len));

    uint8_t *srr = NULL, *sig = NULL;
    size_t srr_len, sig_len;
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_finish_redemption(
        client.get(), &srr, &srr_len, &sig, &sig_len, redeem_resp, resp_len));
    bssl::UniquePtr<uint8_t> free_srr(srr);
    bssl::UniquePtr<uint8_t> free_sig(sig);

    if (!method()->has_srr) {
      size_t b64_len;
      ASSERT_TRUE(EVP_EncodedLength(&b64_len, expected_srr_len));
      b64_len -= 1;
      const char kSRRHeader[] = "body=:";
      ASSERT_LT(sizeof(kSRRHeader) - 1 + b64_len, srr_len);

      ASSERT_EQ(Bytes(kSRRHeader, sizeof(kSRRHeader) - 1),
                Bytes(srr, sizeof(kSRRHeader) - 1));
      uint8_t *decoded_srr =
          (uint8_t *)OPENSSL_malloc(expected_srr_len + 2);
      ASSERT_TRUE(decoded_srr);
      ASSERT_LE(
          int(expected_srr_len),
          EVP_DecodeBlock(decoded_srr, srr + sizeof(kSRRHeader) - 1, b64_len));
      srr = decoded_srr;
      srr_len = expected_srr_len;
      free_srr.reset(srr);
    }

    const uint8_t kTokenHashDSTLabel[] = "TrustTokenV0 TokenHash";
    uint8_t token_hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, kTokenHashDSTLabel, sizeof(kTokenHashDSTLabel));
    SHA256_Update(&sha_ctx, token->data, token->len);
    SHA256_Final(token_hash, &sha_ctx);

    // Check the token hash is in the SRR.
    ASSERT_EQ(Bytes(token_hash), Bytes(srr + 41, sizeof(token_hash)));

    uint8_t decode_private_metadata;
    ASSERT_TRUE(TRUST_TOKEN_decode_private_metadata(
        method(), &decode_private_metadata, metadata_key,
        sizeof(metadata_key), token_hash, sizeof(token_hash), srr[27]));
    ASSERT_EQ(srr[18], public_metadata());
    ASSERT_EQ(decode_private_metadata, private_metadata());

    // Clear out the metadata bits.
    srr[18] = 0;
    srr[27] = 0;

    // Clear out the token hash.
    OPENSSL_memset(srr + 41, 0, sizeof(token_hash));

    ASSERT_EQ(Bytes(expected_srr, expected_srr_len),
              Bytes(srr, srr_len));
  }
}

TEST_P(TrustTokenMetadataTest, RawSetAndGetMetadata) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  bool result = TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      public_metadata(), private_metadata(), /*max_issuance=*/1);
  if (!method()->has_private_metadata && private_metadata()) {
    ASSERT_FALSE(result);
    return;
  }
  ASSERT_TRUE(result);
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);
  EXPECT_EQ(1u, sk_TRUST_TOKEN_num(tokens.get()));

  for (TRUST_TOKEN *token : tokens.get()) {
    const uint8_t kClientData[] = "\x70TEST CLIENT DATA";
    uint64_t kRedemptionTime = (method()->has_srr ? 13374242 : 0);

    uint8_t *redeem_msg = NULL;
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_redemption(
        client.get(), &redeem_msg, &msg_len, token, kClientData,
        sizeof(kClientData) - 1, kRedemptionTime));
    bssl::UniquePtr<uint8_t> free_redeem_msg(redeem_msg);
    uint32_t public_value;
    uint8_t private_value;
    TRUST_TOKEN *rtoken;
    uint8_t *client_data;
    size_t client_data_len;
    ASSERT_TRUE(TRUST_TOKEN_ISSUER_redeem_raw(
        issuer.get(), &public_value, &private_value, &rtoken,
        &client_data, &client_data_len, redeem_msg, msg_len));
    bssl::UniquePtr<uint8_t> free_client_data(client_data);
    bssl::UniquePtr<TRUST_TOKEN> free_rtoken(rtoken);

    ASSERT_EQ(Bytes(kClientData, sizeof(kClientData) - 1),
              Bytes(client_data, client_data_len));
    ASSERT_EQ(public_value, static_cast<uint32_t>(public_metadata()));
    ASSERT_EQ(private_value, private_metadata());
  }
}

TEST_P(TrustTokenMetadataTest, TooManyRequests) {
  if (!method()->has_private_metadata && private_metadata()) {
    return;
  }

  issuer_max_batchsize = 1;
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      public_metadata(), private_metadata(), /*max_issuance=*/1));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  ASSERT_EQ(tokens_issued, issuer_max_batchsize);
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);
  ASSERT_EQ(sk_TRUST_TOKEN_num(tokens.get()), 1UL);
}


TEST_P(TrustTokenMetadataTest, TruncatedProof) {
  if (!method()->has_private_metadata && private_metadata()) {
    return;
  }

  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      public_metadata(), private_metadata(), /*max_issuance=*/1));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);

  CBS real_response;
  CBS_init(&real_response, issue_resp, resp_len);
  uint16_t count;
  uint32_t parsed_public_metadata;
  bssl::ScopedCBB bad_response;
  ASSERT_TRUE(CBB_init(bad_response.get(), 0));
  ASSERT_TRUE(CBS_get_u16(&real_response, &count));
  ASSERT_TRUE(CBB_add_u16(bad_response.get(), count));
  ASSERT_TRUE(CBS_get_u32(&real_response, &parsed_public_metadata));
  ASSERT_TRUE(CBB_add_u32(bad_response.get(), parsed_public_metadata));

  const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
  size_t token_length =
      TRUST_TOKEN_NONCE_SIZE + 2 * (1 + 2 * BN_num_bytes(&group->field));
  if (method() == TRUST_TOKEN_experiment_v1()) {
    token_length += 4;
  }
  if (method() == TRUST_TOKEN_experiment_v2_voprf()) {
    token_length = 1 + 2 * BN_num_bytes(&group->field);
  }
  for (size_t i = 0; i < count; i++) {
    ASSERT_TRUE(CBB_add_bytes(bad_response.get(), CBS_data(&real_response),
                              token_length));
    ASSERT_TRUE(CBS_skip(&real_response, token_length));
  }

  CBS tmp;
  ASSERT_TRUE(CBS_get_u16_length_prefixed(&real_response, &tmp));
  CBB dleq;
  ASSERT_TRUE(CBB_add_u16_length_prefixed(bad_response.get(), &dleq));
  ASSERT_TRUE(CBB_add_bytes(&dleq, CBS_data(&tmp), CBS_len(&tmp) - 2));
  ASSERT_TRUE(CBB_flush(bad_response.get()));

  uint8_t *bad_buf;
  size_t bad_len;
  ASSERT_TRUE(CBB_finish(bad_response.get(), &bad_buf, &bad_len));
  bssl::UniquePtr<uint8_t> free_bad(bad_buf);

  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, bad_buf,
                                         bad_len));
  ASSERT_FALSE(tokens);
}

TEST_P(TrustTokenMetadataTest, ExcessDataProof) {
  if (!method()->has_private_metadata && private_metadata()) {
    return;
  }

  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      public_metadata(), private_metadata(), /*max_issuance=*/1));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);

  CBS real_response;
  CBS_init(&real_response, issue_resp, resp_len);
  uint16_t count;
  uint32_t parsed_public_metadata;
  bssl::ScopedCBB bad_response;
  ASSERT_TRUE(CBB_init(bad_response.get(), 0));
  ASSERT_TRUE(CBS_get_u16(&real_response, &count));
  ASSERT_TRUE(CBB_add_u16(bad_response.get(), count));
  ASSERT_TRUE(CBS_get_u32(&real_response, &parsed_public_metadata));
  ASSERT_TRUE(CBB_add_u32(bad_response.get(), parsed_public_metadata));

  const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
  size_t token_length =
      TRUST_TOKEN_NONCE_SIZE + 2 * (1 + 2 * BN_num_bytes(&group->field));
  if (method() == TRUST_TOKEN_experiment_v1()) {
    token_length += 4;
  }
  if (method() == TRUST_TOKEN_experiment_v2_voprf()) {
    token_length = 1 + 2 * BN_num_bytes(&group->field);
  }
  for (size_t i = 0; i < count; i++) {
    ASSERT_TRUE(CBB_add_bytes(bad_response.get(), CBS_data(&real_response),
                              token_length));
    ASSERT_TRUE(CBS_skip(&real_response, token_length));
  }

  CBS tmp;
  ASSERT_TRUE(CBS_get_u16_length_prefixed(&real_response, &tmp));
  CBB dleq;
  ASSERT_TRUE(CBB_add_u16_length_prefixed(bad_response.get(), &dleq));
  ASSERT_TRUE(CBB_add_bytes(&dleq, CBS_data(&tmp), CBS_len(&tmp)));
  ASSERT_TRUE(CBB_add_u16(&dleq, 42));
  ASSERT_TRUE(CBB_flush(bad_response.get()));

  uint8_t *bad_buf;
  size_t bad_len;
  ASSERT_TRUE(CBB_finish(bad_response.get(), &bad_buf, &bad_len));
  bssl::UniquePtr<uint8_t> free_bad(bad_buf);

  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, bad_buf,
                                         bad_len));
  ASSERT_FALSE(tokens);
}

INSTANTIATE_TEST_SUITE_P(
    TrustTokenAllMetadataTest, TrustTokenMetadataTest,
    testing::Combine(testing::ValuesIn(AllMethods()),
                     testing::Values(TrustTokenProtocolTest::KeyID(0),
                                     TrustTokenProtocolTest::KeyID(1),
                                     TrustTokenProtocolTest::KeyID(2)),
                     testing::Bool()));

class TrustTokenBadKeyTest
    : public TrustTokenProtocolTestBase,
      public testing::WithParamInterface<
          std::tuple<const TRUST_TOKEN_METHOD *, bool, int>> {
 public:
  TrustTokenBadKeyTest()
      : TrustTokenProtocolTestBase(std::get<0>(GetParam())) {}

  bool private_metadata() { return std::get<1>(GetParam()); }
  int corrupted_key() { return std::get<2>(GetParam()); }
};

TEST_P(TrustTokenBadKeyTest, BadKey) {
  // For versions without private metadata, only corruptions of 'xs' (the 4th
  // entry in |scalars| below) result in a bad key, as the other scalars are
  // unused internally.
  if (!method()->has_private_metadata &&
      (private_metadata() || corrupted_key() != 4)) {
    return;
  }

  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);

  struct trust_token_issuer_key_st *key = &issuer->keys[0];
  EC_SCALAR *scalars[] = {&key->key.x0, &key->key.y0, &key->key.x1,
                          &key->key.y1, &key->key.xs, &key->key.ys};

  // Corrupt private key scalar.
  scalars[corrupted_key()]->words[0] ^= 42;

  size_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/7, private_metadata(), /*max_issuance=*/1));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));

  // If the unused private key is corrupted, then the DLEQ proof should succeed.
  if ((corrupted_key() / 2 == 0 && private_metadata() == true) ||
      (corrupted_key() / 2 == 1 && private_metadata() == false)) {
    ASSERT_TRUE(tokens);
  } else {
    ASSERT_FALSE(tokens);
  }
}

INSTANTIATE_TEST_SUITE_P(TrustTokenAllBadKeyTest, TrustTokenBadKeyTest,
                         testing::Combine(testing::ValuesIn(AllMethods()),
                                          testing::Bool(),
                                          testing::Values(0, 1, 2, 3, 4, 5)));

}  // namespace
BSSL_NAMESPACE_END
