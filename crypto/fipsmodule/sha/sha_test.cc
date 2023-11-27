/* Copyright (c) 2018, Google Inc.
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

#include <openssl/sha.h>

#include <gtest/gtest.h>

#include "internal.h"
#include "../../test/abi_test.h"


#if defined(SHA1_ASM) && defined(SUPPORTS_ABI_TEST)

typedef void (*sha1_block_f)(uint32_t *state, const uint8_t *data,
                             size_t num);

class SHA1BlockTest : public testing::TestWithParam<sha1_block_f> {};

TEST_P(SHA1BlockTest, SHA256ABI) {
  SHA_CTX ctx;
  SHA1_Init(&ctx);

  auto f = GetParam();

  static const uint8_t kBuf[SHA_CBLOCK * 8] = {0};
  CHECK_ABI(f, ctx.h, kBuf, 1);
  CHECK_ABI(f, ctx.h, kBuf, 2);
  CHECK_ABI(f, ctx.h, kBuf, 4);
  CHECK_ABI(f, ctx.h, kBuf, 8);
}

const sha1_block_f kSha1BlockFunctions[] = {
#if defined(SHA_ASM_SPLIT)
  sha1_block_data_order_hw,
  sha1_block_data_order_nohw,
#else
  sha1_block_data_order,
#endif
};

INSTANTIATE_TEST_SUITE_P(All, SHA1BlockTest,
                         testing::ValuesIn(kSha1BlockFunctions));

#endif  // SHA1_ASM && SUPPORTS_ABI_TEST

#if defined(SHA256_ASM) && defined(SUPPORTS_ABI_TEST)

typedef void (*sha256_block_f)(uint32_t *state, const uint8_t *data,
                               size_t num);

class SHA256BlockTest : public testing::TestWithParam<sha256_block_f> {};

TEST_P(SHA256BlockTest, SHA256ABI) {
  SHA256_CTX ctx;
  SHA256_Init(&ctx);

  auto f = GetParam();

  static const uint8_t kBuf[SHA256_CBLOCK * 8] = {0};
  CHECK_ABI(f, ctx.h, kBuf, 1);
  CHECK_ABI(f, ctx.h, kBuf, 2);
  CHECK_ABI(f, ctx.h, kBuf, 4);
  CHECK_ABI(f, ctx.h, kBuf, 8);
}

const sha256_block_f kSha256BlockFunctions[] = {
#if defined(SHA_ASM_SPLIT)
  sha256_block_data_order_hw,
  sha256_block_data_order_nohw,
#else
  sha256_block_data_order,
#endif
};

INSTANTIATE_TEST_SUITE_P(All, SHA256BlockTest,
                         testing::ValuesIn(kSha256BlockFunctions));


#endif  // SHA256_ASM && SUPPORTS_ABI_TEST

#if defined(SHA512_ASM) && defined(SUPPORTS_ABI_TEST)

typedef void (*sha512_block_f)(uint64_t *state, const uint8_t *data,
                               size_t num);

class SHA512BlockTest : public testing::TestWithParam<sha512_block_f> {};

TEST_P(SHA512BlockTest, SHA512ABI) {
  SHA512_CTX ctx;
  SHA512_Init(&ctx);

  auto f = GetParam();

  static const uint8_t kBuf[SHA512_CBLOCK * 4] = {0};
  CHECK_ABI(f, ctx.h, kBuf, 1);
  CHECK_ABI(f, ctx.h, kBuf, 2);
  CHECK_ABI(f, ctx.h, kBuf, 3);
  CHECK_ABI(f, ctx.h, kBuf, 4);
}

const sha512_block_f kSha512BlockFunctions[] = {
#if defined(SHA_ASM_SPLIT)
  sha512_block_data_order_hw, sha512_block_data_order_nohw
#else
  sha512_block_data_order
#endif
};

INSTANTIATE_TEST_SUITE_P(All, SHA512BlockTest,
                         testing::ValuesIn(kSha512BlockFunctions));


#endif  // SHA512_ASM && SUPPORTS_ABI_TEST
