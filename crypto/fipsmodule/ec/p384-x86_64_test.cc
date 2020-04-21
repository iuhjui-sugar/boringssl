/* Copyright (c) 2016, Google Inc.
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

#include <string.h>

#include <gtest/gtest.h>

#include <openssl/ec.h>

#include "internal.h"
#include "../../test/abi_test.h"
#include "../../test/file_test.h"
#include "../../test/test_util.h"
#include "p384-x86_64.h"


// Disable tests if BORINGSSL_SHARED_LIBRARY is defined. These tests need access
// to internal functions.
#if !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86_64) && \
    !defined(OPENSSL_SMALL) && !defined(BORINGSSL_SHARED_LIBRARY)

TEST(P384_X86_64Test, SelectW7) {
  // Fill a table with some garbage input.
  alignas(64) P384_POINT_AFFINE table[64];
  for (size_t i = 0; i < 64; i++) {
    OPENSSL_memset(table[i].X, 2 * i, sizeof(table[i].X));
    OPENSSL_memset(table[i].Y, 2 * i + 1, sizeof(table[i].Y));
  }

  for (int i = 0; i <= 64; i++) {
    P384_POINT_AFFINE val;
    ecp_nistp384_select_w7(&val, table, i);

    P384_POINT_AFFINE expected;
    if (i == 0) {
      OPENSSL_memset(&expected, 0, sizeof(expected));
    } else {
      expected = table[i-1];
    }

    EXPECT_EQ(Bytes(reinterpret_cast<const char *>(&expected), sizeof(expected)),
              Bytes(reinterpret_cast<const char *>(&val), sizeof(val)));
  }

  // This is a constant-time function, so it is only necessary to instrument one
  // index for ABI checking.
  P384_POINT_AFFINE val;
  CHECK_ABI(ecp_nistp384_select_w7, &val, table, 42);
}

#endif
