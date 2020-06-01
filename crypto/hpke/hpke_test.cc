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

#include <openssl/aead.h>
#include <openssl/base.h>
#include <openssl/digest.h>
#include <openssl/err.h>

#include <gtest/gtest.h>

#include "../test/file_test.h"
#include "../test/test_util.h"

#include "internal.h"

// Test vectors from
// https://www.ietf.org/id/draft-irtf-cfrg-hpke-04.html#name-test-vectors

/*
  DHKEM(Curve25519, HKDF-SHA256), HKDF-SHA256, AES-GCM-128

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
*/

TEST(HPKETest, Trivial) {
  EVP_HPKE_CTX ctx;
  EVP_HPKE_CTX_init(&ctx);
  EVP_HPKE_CTX_cleanup(&ctx);
}

TEST(HPKETest, TrivialWithSetupBaseS) {
  EVP_HPKE_CTX ctx;
  EVP_HPKE_CTX_init(&ctx);

  uint8_t enc[X25519_PUBLIC_VALUE_LEN];

  uint8_t public_key[X25519_PUBLIC_VALUE_LEN];
  uint8_t private_key[X25519_PRIVATE_KEY_LEN];
  X25519_keypair(public_key, private_key);

  EXPECT_TRUE(EVP_HPKE_CTX_setup_base_x25519_s(&ctx, enc, public_key, NULL, 0));

  EVP_HPKE_CTX_cleanup(&ctx);
}
