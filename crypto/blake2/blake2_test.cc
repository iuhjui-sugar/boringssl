/* Copyright (c) 2021, Google Inc.
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

#include <openssl/blake2.h>

#include <gtest/gtest.h>

#include "../test/file_test.h"
#include "../test/test_util.h"

TEST(BLAKE2B512Test, ABC) {
  // https://tools.ietf.org/html/rfc7693#appendix-A
  const uint8_t kExpected[] = {
      0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d, 0x6a, 0x27, 0x97,
      0xb6, 0x9f, 0x12, 0xf6, 0xe9, 0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a,
      0xc4, 0xb7, 0x4b, 0x12, 0xbb, 0x6f, 0xdb, 0xff, 0xa2, 0xd1, 0x7d,
      0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d, 0xc2, 0x52, 0xd5, 0xde,
      0x45, 0x33, 0xcc, 0x95, 0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92,
      0x5a, 0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23,
  };

  uint8_t digest[BLAKE2B512_DIGEST_LENGTH];
  BLAKE2B512((const uint8_t *)"abc", 3, digest);
  EXPECT_EQ(Bytes(kExpected), Bytes(digest));
}

TEST(BLAKE2B512Test, TestVectors) {
  FileTestGTest("crypto/blake2/blake2b512_tests.txt", [](FileTest *t) {
    std::vector<uint8_t> msg, expected;
    ASSERT_TRUE(t->GetBytes(&msg, "IN"));
    ASSERT_TRUE(t->GetBytes(&expected, "HASH"));

    uint8_t digest[BLAKE2B512_DIGEST_LENGTH];
    BLAKE2B512(msg.data(), msg.size(), digest);
    EXPECT_EQ(Bytes(digest), Bytes(expected)) << msg.size();
  });
}
