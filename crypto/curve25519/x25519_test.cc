/* Copyright (c) 2015, Google Inc.
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <gtest/gtest.h>

#include <openssl/curve25519.h>

#include "../internal.h"
#include "../test/file_test.h"
#include "../test/test_util.h"


TEST(X25519Test, TestVector) {
  FileTestGTest("crypto/curve25519/x25519_tests.txt", [](FileTest *t) {
    std::vector<uint8_t> sk, pk, ss;
    std::string valid;
    ASSERT_TRUE(t->GetBytes(&sk, "SK"));
    ASSERT_EQ(32u, sk.size());
    ASSERT_TRUE(t->GetBytes(&pk, "PK"));
    ASSERT_EQ(32u, pk.size());
    ASSERT_TRUE(t->GetBytes(&ss, "SS"));
    ASSERT_EQ(32u, ss.size());

    uint8_t out[32] = {0};
    if (!t->HasAttribute("FAIL")) {
      EXPECT_TRUE(X25519(out, sk.data(), pk.data()));
    } else {
      EXPECT_FALSE(X25519(out, sk.data(), pk.data()));
    }

    EXPECT_EQ(Bytes(ss), Bytes(out));
  });
}

TEST(X25519Test, SmallOrder) {
  static const uint8_t kSmallOrderPoint[32] = {
      0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
      0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
      0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8,
  };

  uint8_t out[32], private_key[32];
  OPENSSL_memset(private_key, 0x11, sizeof(private_key));

  OPENSSL_memset(out, 0xff, sizeof(out));
  EXPECT_FALSE(X25519(out, private_key, kSmallOrderPoint))
      << "X25519 returned success with a small-order input.";

  // For callers which don't check, |out| should still be filled with zeros.
  static const uint8_t kZeros[32] = {0};
  EXPECT_EQ(Bytes(kZeros), Bytes(out));
}

TEST(X25519Test, Iterated) {
  // Taken from https://tools.ietf.org/html/rfc7748#section-5.2.
  uint8_t scalar[32] = {9}, point[32] = {9}, out[32];

  for (unsigned i = 0; i < 1000; i++) {
    EXPECT_TRUE(X25519(out, scalar, point));
    OPENSSL_memcpy(point, scalar, sizeof(point));
    OPENSSL_memcpy(scalar, out, sizeof(scalar));
  }

  static const uint8_t kExpected[32] = {
      0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55, 0x28, 0x00, 0xef,
      0x56, 0x6f, 0x2f, 0x4d, 0x3c, 0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60,
      0xe3, 0x87, 0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51,
  };

  EXPECT_EQ(Bytes(kExpected), Bytes(scalar));
}

TEST(X25519Test, DISABLED_IteratedLarge) {
  // Taken from https://tools.ietf.org/html/rfc7748#section-5.2.
  uint8_t scalar[32] = {9}, point[32] = {9}, out[32];

  for (unsigned i = 0; i < 1000000; i++) {
    EXPECT_TRUE(X25519(out, scalar, point));
    OPENSSL_memcpy(point, scalar, sizeof(point));
    OPENSSL_memcpy(scalar, out, sizeof(scalar));
  }

  static const uint8_t kExpected[32] = {
      0x7c, 0x39, 0x11, 0xe0, 0xab, 0x25, 0x86, 0xfd, 0x86, 0x44, 0x97,
      0x29, 0x7e, 0x57, 0x5e, 0x6f, 0x3b, 0xc6, 0x01, 0xc0, 0x88, 0x3c,
      0x30, 0xdf, 0x5f, 0x4d, 0xd2, 0xd2, 0x4f, 0x66, 0x54, 0x24,
  };

  EXPECT_EQ(Bytes(kExpected), Bytes(scalar));
}
