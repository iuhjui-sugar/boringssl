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

#include <openssl/base.h>

#include <stdio.h>
#include <string.h>

#include <gtest/gtest.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/mem.h>
#include <openssl/nid.h>

#include "internal.h"
#include "../bn/internal.h"
#include "../../internal.h"
#include "../../test/abi_test.h"
#include "../../test/file_test.h"
#include "../../test/test_util.h"
#include "p256-nistz.h"


// Disable tests if BORINGSSL_SHARED_LIBRARY is defined. These tests need access
// to internal functions.
#if !defined(OPENSSL_NO_ASM) &&  \
    (defined(OPENSSL_X86_64) || defined(OPENSSL_AARCH64)) &&  \
    !defined(OPENSSL_SMALL) && !defined(BORINGSSL_SHARED_LIBRARY)

TEST(P256_NistzTest, SelectW5) {
  // Fill a table with some garbage input.
  alignas(64) P256_POINT table[16];
  for (size_t i = 0; i < 16; i++) {
    OPENSSL_memset(table[i].X, static_cast<uint8_t>(3 * i), sizeof(table[i].X));
    OPENSSL_memset(table[i].Y, static_cast<uint8_t>(3 * i + 1),
                   sizeof(table[i].Y));
    OPENSSL_memset(table[i].Z, static_cast<uint8_t>(3 * i + 2),
                   sizeof(table[i].Z));
  }

  for (int i = 0; i <= 16; i++) {
    P256_POINT val;
    ecp_nistz256_select_w5(&val, table, i);

    P256_POINT expected;
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
  P256_POINT val;
  CHECK_ABI(ecp_nistz256_select_w5, &val, table, 7);
}

TEST(P256_NistzTest, BEEU) {
#if defined(OPENSSL_X86_64)
  if (!CRYPTO_is_AVX_capable()) {
    // No AVX support; cannot run the BEEU code.
    return;
  }
#endif

  const EC_GROUP *group = EC_group_p256();
  BN_ULONG order_words[P256_LIMBS];
  ASSERT_TRUE(
      bn_copy_words(order_words, P256_LIMBS, EC_GROUP_get0_order(group)));

  BN_ULONG in[P256_LIMBS], out[P256_LIMBS];
  EC_SCALAR in_scalar, out_scalar, result;
  OPENSSL_memset(in, 0, sizeof(in));

  // Trying to find the inverse of zero should fail.
  ASSERT_FALSE(beeu_mod_inverse_vartime(out, in, order_words));
  // This is not a constant-time function, so instrument both zero and a few
  // inputs below.
  ASSERT_FALSE(CHECK_ABI(beeu_mod_inverse_vartime, out, in, order_words));

  // kOneMont is 1, in Montgomery form.
  static const BN_ULONG kOneMont[P256_LIMBS] = {
      TOBN(0xc46353d, 0x039cdaaf),
      TOBN(0x43190552, 0x58e8617b),
      0,
      0xffffffff,
  };

  for (BN_ULONG i = 1; i < 2000; i++) {
    SCOPED_TRACE(i);

    in[0] = i;
    if (i >= 1000) {
      in[1] = i << 8;
      in[2] = i << 32;
      in[3] = i << 48;
    } else {
      in[1] = in[2] = in[3] = 0;
    }

    EXPECT_TRUE(bn_less_than_words(in, order_words, P256_LIMBS));
    ASSERT_TRUE(beeu_mod_inverse_vartime(out, in, order_words));
    EXPECT_TRUE(bn_less_than_words(out, order_words, P256_LIMBS));

    // Calculate out*in and confirm that it equals one, modulo the order.
    OPENSSL_memcpy(in_scalar.words, in, sizeof(in));
    OPENSSL_memcpy(out_scalar.words, out, sizeof(out));
    ec_scalar_to_montgomery(group, &in_scalar, &in_scalar);
    ec_scalar_to_montgomery(group, &out_scalar, &out_scalar);
    ec_scalar_mul_montgomery(group, &result, &in_scalar, &out_scalar);

    EXPECT_EQ(0, OPENSSL_memcmp(kOneMont, &result, sizeof(kOneMont)));

    // Invert the result and expect to get back to the original value.
    ASSERT_TRUE(beeu_mod_inverse_vartime(out, out, order_words));
    EXPECT_EQ(0, OPENSSL_memcmp(in, out, sizeof(in)));

    if (i < 5) {
      EXPECT_TRUE(CHECK_ABI(beeu_mod_inverse_vartime, out, in, order_words));
    }
  }
}

static bool GetFieldElement(FileTest *t, BN_ULONG out[P256_LIMBS],
                            const char *name) {
  std::vector<uint8_t> bytes;
  if (!t->GetBytes(&bytes, name)) {
    return false;
  }

  if (bytes.size() != BN_BYTES * P256_LIMBS) {
    ADD_FAILURE() << "Invalid length: " << name;
    return false;
  }

  // |byte| contains bytes in big-endian while |out| should contain |BN_ULONG|s
  // in little-endian.
  OPENSSL_memset(out, 0, P256_LIMBS * sizeof(BN_ULONG));
  for (size_t i = 0; i < bytes.size(); i++) {
    out[P256_LIMBS - 1 - (i / BN_BYTES)] <<= 8;
    out[P256_LIMBS - 1 - (i / BN_BYTES)] |= bytes[i];
  }

  return true;
}

static std::string FieldElementToString(const BN_ULONG a[P256_LIMBS]) {
  std::string ret;
  for (size_t i = P256_LIMBS-1; i < P256_LIMBS; i--) {
    char buf[2 * BN_BYTES + 1];
    snprintf(buf, sizeof(buf), BN_HEX_FMT2, a[i]);
    ret += buf;
  }
  return ret;
}

static testing::AssertionResult ExpectFieldElementsEqual(
    const char *expected_expr, const char *actual_expr,
    const BN_ULONG expected[P256_LIMBS], const BN_ULONG actual[P256_LIMBS]) {
  if (OPENSSL_memcmp(expected, actual, sizeof(BN_ULONG) * P256_LIMBS) == 0) {
    return testing::AssertionSuccess();
  }

  return testing::AssertionFailure()
         << "Expected: " << FieldElementToString(expected) << " ("
         << expected_expr << ")\n"
         << "Actual:   " << FieldElementToString(actual) << " (" << actual_expr
         << ")";
}

#define EXPECT_FIELD_ELEMENTS_EQUAL(a, b) \
  EXPECT_PRED_FORMAT2(ExpectFieldElementsEqual, a, b)

#define EXPECT_POINTS_EQUAL(a, b) EXPECT_PRED_FORMAT2(ExpectPointsEqual, a, b)

static void TestFromMont(FileTest *t) {
  BN_ULONG a[P256_LIMBS], result[P256_LIMBS];
  ASSERT_TRUE(GetFieldElement(t, a, "A"));
  ASSERT_TRUE(GetFieldElement(t, result, "Result"));

  BN_ULONG ret[P256_LIMBS];
  ecp_nistz256_from_mont(ret, a);
  EXPECT_FIELD_ELEMENTS_EQUAL(result, ret);

  OPENSSL_memcpy(ret, a, sizeof(ret));
  ecp_nistz256_from_mont(ret, ret /* a */);
  EXPECT_FIELD_ELEMENTS_EQUAL(result, ret);
}

static void TestOrdMulMont(FileTest *t) {
  // This test works on scalars rather than field elements, but the
  // representation is the same.
  BN_ULONG a[P256_LIMBS], b[P256_LIMBS], result[P256_LIMBS];
  ASSERT_TRUE(GetFieldElement(t, a, "A"));
  ASSERT_TRUE(GetFieldElement(t, b, "B"));
  ASSERT_TRUE(GetFieldElement(t, result, "Result"));

  BN_ULONG ret[P256_LIMBS];
  ecp_nistz256_ord_mul_mont(ret, a, b);
  EXPECT_FIELD_ELEMENTS_EQUAL(result, ret);

  ecp_nistz256_ord_mul_mont(ret, b, a);
  EXPECT_FIELD_ELEMENTS_EQUAL(result, ret);

  OPENSSL_memcpy(ret, a, sizeof(ret));
  ecp_nistz256_ord_mul_mont(ret, ret /* a */, b);
  EXPECT_FIELD_ELEMENTS_EQUAL(result, ret);

  OPENSSL_memcpy(ret, a, sizeof(ret));
  ecp_nistz256_ord_mul_mont(ret, b, ret);
  EXPECT_FIELD_ELEMENTS_EQUAL(result, ret);

  OPENSSL_memcpy(ret, b, sizeof(ret));
  ecp_nistz256_ord_mul_mont(ret, a, ret /* b */);
  EXPECT_FIELD_ELEMENTS_EQUAL(result, ret);

  OPENSSL_memcpy(ret, b, sizeof(ret));
  ecp_nistz256_ord_mul_mont(ret, ret /* b */, a);
  EXPECT_FIELD_ELEMENTS_EQUAL(result, ret);

  if (OPENSSL_memcmp(a, b, sizeof(a)) == 0) {
    ecp_nistz256_ord_sqr_mont(ret, a, 1);
    EXPECT_FIELD_ELEMENTS_EQUAL(result, ret);

    OPENSSL_memcpy(ret, a, sizeof(ret));
    ecp_nistz256_ord_sqr_mont(ret, ret /* a */, 1);
    EXPECT_FIELD_ELEMENTS_EQUAL(result, ret);
  }
}

TEST(P256_NistzTest, TestVectors) {
  return FileTestGTest("crypto/fipsmodule/ec/p256-nistz_tests.txt",
                       [](FileTest *t) {
    if (t->GetParameter() == "Negate") {
      // TestNegate(t);
    } else if (t->GetParameter() == "MulMont") {
      // TestMulMont(t);
    } else if (t->GetParameter() == "FromMont") {
      TestFromMont(t);
    } else if (t->GetParameter() == "PointAdd") {
      // TestPointAdd(t);
    } else if (t->GetParameter() == "OrdMulMont") {
      TestOrdMulMont(t);
    } else {
      FAIL() << "Unknown test type:" << t->GetParameter();
    }
  });
}

#endif
