/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the Eric Young open source
 * license provided above.
 *
 * The binary polynomial arithmetic software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems
 * Laboratories. */

/* Per C99, various stdint.h and inttypes.h macros (the latter used by bn.h) are
 * unavailable in C++ unless some macros are defined. C++11 overruled this
 * decision, but older Android NDKs still require it. */
#if !defined(__STDC_CONSTANT_MACROS)
#define __STDC_CONSTANT_MACROS
#endif
#if !defined(__STDC_FORMAT_MACROS)
#define __STDC_FORMAT_MACROS
#endif

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <utility>

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "../internal.h"
#include "../test/file_test.h"
#include "../test/test_util.h"


static int HexToBIGNUM(bssl::UniquePtr<BIGNUM> *out, const char *in) {
  BIGNUM *raw = NULL;
  int ret = BN_hex2bn(&raw, in);
  out->reset(raw);
  return ret;
}

static bssl::UniquePtr<BIGNUM> GetBIGNUM(FileTest *t, const char *attribute) {
  std::string hex;
  if (!t->GetAttribute(&hex, attribute)) {
    return nullptr;
  }

  bssl::UniquePtr<BIGNUM> ret;
  if (HexToBIGNUM(&ret, hex.c_str()) != static_cast<int>(hex.size())) {
    t->PrintLine("Could not decode '%s'.", hex.c_str());
    return nullptr;
  }
  return ret;
}

static bool GetInt(FileTest *t, int *out, const char *attribute) {
  bssl::UniquePtr<BIGNUM> ret = GetBIGNUM(t, attribute);
  if (!ret) {
    return false;
  }

  BN_ULONG word = BN_get_word(ret.get());
  if (word > INT_MAX) {
    return false;
  }

  *out = static_cast<int>(word);
  return true;
}

static bool ExpectBIGNUMsEqual(FileTest *t, const char *operation,
                               const BIGNUM *expected, const BIGNUM *actual) {
  if (BN_cmp(expected, actual) == 0) {
    return true;
  }

  bssl::UniquePtr<char> expected_str(BN_bn2hex(expected));
  bssl::UniquePtr<char> actual_str(BN_bn2hex(actual));
  if (!expected_str || !actual_str) {
    return false;
  }

  t->PrintLine("Got %s =", operation);
  t->PrintLine("\t%s", actual_str.get());
  t->PrintLine("wanted:");
  t->PrintLine("\t%s", expected_str.get());
  return false;
}

static bool TestSum(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> a = GetBIGNUM(t, "A");
  bssl::UniquePtr<BIGNUM> b = GetBIGNUM(t, "B");
  bssl::UniquePtr<BIGNUM> sum = GetBIGNUM(t, "Sum");
  if (!a || !b || !sum) {
    return false;
  }

  bssl::UniquePtr<BIGNUM> ret(BN_new());
  if (!ret ||
      !BN_add(ret.get(), a.get(), b.get()) ||
      !ExpectBIGNUMsEqual(t, "A + B", sum.get(), ret.get()) ||
      !BN_sub(ret.get(), sum.get(), a.get()) ||
      !ExpectBIGNUMsEqual(t, "Sum - A", b.get(), ret.get()) ||
      !BN_sub(ret.get(), sum.get(), b.get()) ||
      !ExpectBIGNUMsEqual(t, "Sum - B", a.get(), ret.get())) {
    return false;
  }

  // Test that the functions work when |r| and |a| point to the same |BIGNUM|,
  // or when |r| and |b| point to the same |BIGNUM|. TODO: Test the case where
  // all of |r|, |a|, and |b| point to the same |BIGNUM|.
  if (!BN_copy(ret.get(), a.get()) ||
      !BN_add(ret.get(), ret.get(), b.get()) ||
      !ExpectBIGNUMsEqual(t, "A + B (r is a)", sum.get(), ret.get()) ||
      !BN_copy(ret.get(), b.get()) ||
      !BN_add(ret.get(), a.get(), ret.get()) ||
      !ExpectBIGNUMsEqual(t, "A + B (r is b)", sum.get(), ret.get()) ||
      !BN_copy(ret.get(), sum.get()) ||
      !BN_sub(ret.get(), ret.get(), a.get()) ||
      !ExpectBIGNUMsEqual(t, "Sum - A (r is a)", b.get(), ret.get()) ||
      !BN_copy(ret.get(), a.get()) ||
      !BN_sub(ret.get(), sum.get(), ret.get()) ||
      !ExpectBIGNUMsEqual(t, "Sum - A (r is b)", b.get(), ret.get()) ||
      !BN_copy(ret.get(), sum.get()) ||
      !BN_sub(ret.get(), ret.get(), b.get()) ||
      !ExpectBIGNUMsEqual(t, "Sum - B (r is a)", a.get(), ret.get()) ||
      !BN_copy(ret.get(), b.get()) ||
      !BN_sub(ret.get(), sum.get(), ret.get()) ||
      !ExpectBIGNUMsEqual(t, "Sum - B (r is b)", a.get(), ret.get())) {
    return false;
  }

  // Test |BN_uadd| and |BN_usub| with the prerequisites they are documented as
  // having. Note that these functions are frequently used when the
  // prerequisites don't hold. In those cases, they are supposed to work as if
  // the prerequisite hold, but we don't test that yet. TODO: test that.
  if (!BN_is_negative(a.get()) &&
      !BN_is_negative(b.get()) && BN_cmp(a.get(), b.get()) >= 0) {
    if (!BN_uadd(ret.get(), a.get(), b.get()) ||
        !ExpectBIGNUMsEqual(t, "A +u B", sum.get(), ret.get()) ||
        !BN_usub(ret.get(), sum.get(), a.get()) ||
        !ExpectBIGNUMsEqual(t, "Sum -u A", b.get(), ret.get()) ||
        !BN_usub(ret.get(), sum.get(), b.get()) ||
        !ExpectBIGNUMsEqual(t, "Sum -u B", a.get(), ret.get())) {
      return false;
    }

    // Test that the functions work when |r| and |a| point to the same |BIGNUM|,
    // or when |r| and |b| point to the same |BIGNUM|. TODO: Test the case where
    // all of |r|, |a|, and |b| point to the same |BIGNUM|.
    if (!BN_copy(ret.get(), a.get()) ||
        !BN_uadd(ret.get(), ret.get(), b.get()) ||
        !ExpectBIGNUMsEqual(t, "A +u B (r is a)", sum.get(), ret.get()) ||
        !BN_copy(ret.get(), b.get()) ||
        !BN_uadd(ret.get(), a.get(), ret.get()) ||
        !ExpectBIGNUMsEqual(t, "A +u B (r is b)", sum.get(), ret.get()) ||
        !BN_copy(ret.get(), sum.get()) ||
        !BN_usub(ret.get(), ret.get(), a.get()) ||
        !ExpectBIGNUMsEqual(t, "Sum -u A (r is a)", b.get(), ret.get()) ||
        !BN_copy(ret.get(), a.get()) ||
        !BN_usub(ret.get(), sum.get(), ret.get()) ||
        !ExpectBIGNUMsEqual(t, "Sum -u A (r is b)", b.get(), ret.get()) ||
        !BN_copy(ret.get(), sum.get()) ||
        !BN_usub(ret.get(), ret.get(), b.get()) ||
        !ExpectBIGNUMsEqual(t, "Sum -u B (r is a)", a.get(), ret.get()) ||
        !BN_copy(ret.get(), b.get()) ||
        !BN_usub(ret.get(), sum.get(), ret.get()) ||
        !ExpectBIGNUMsEqual(t, "Sum -u B (r is b)", a.get(), ret.get())) {
      return false;
    }
  }

  // Test with |BN_add_word| and |BN_sub_word| if |b| is small enough.
  BN_ULONG b_word = BN_get_word(b.get());
  if (!BN_is_negative(b.get()) && b_word != (BN_ULONG)-1) {
    if (!BN_copy(ret.get(), a.get()) ||
        !BN_add_word(ret.get(), b_word) ||
        !ExpectBIGNUMsEqual(t, "A + B (word)", sum.get(), ret.get()) ||
        !BN_copy(ret.get(), sum.get()) ||
        !BN_sub_word(ret.get(), b_word) ||
        !ExpectBIGNUMsEqual(t, "Sum - B (word)", a.get(), ret.get())) {
      return false;
    }
  }

  return true;
}

static bool TestLShift1(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> a = GetBIGNUM(t, "A");
  bssl::UniquePtr<BIGNUM> lshift1 = GetBIGNUM(t, "LShift1");
  bssl::UniquePtr<BIGNUM> zero(BN_new());
  if (!a || !lshift1 || !zero) {
    return false;
  }

  BN_zero(zero.get());

  bssl::UniquePtr<BIGNUM> ret(BN_new()), two(BN_new()), remainder(BN_new());
  if (!ret || !two || !remainder ||
      !BN_set_word(two.get(), 2) ||
      !BN_add(ret.get(), a.get(), a.get()) ||
      !ExpectBIGNUMsEqual(t, "A + A", lshift1.get(), ret.get()) ||
      !BN_mul(ret.get(), a.get(), two.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "A * 2", lshift1.get(), ret.get()) ||
      !BN_div(ret.get(), remainder.get(), lshift1.get(), two.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "LShift1 / 2", a.get(), ret.get()) ||
      !ExpectBIGNUMsEqual(t, "LShift1 % 2", zero.get(), remainder.get()) ||
      !BN_lshift1(ret.get(), a.get()) ||
      !ExpectBIGNUMsEqual(t, "A << 1", lshift1.get(), ret.get()) ||
      !BN_rshift1(ret.get(), lshift1.get()) ||
      !ExpectBIGNUMsEqual(t, "LShift >> 1", a.get(), ret.get()) ||
      !BN_rshift1(ret.get(), lshift1.get()) ||
      !ExpectBIGNUMsEqual(t, "LShift >> 1", a.get(), ret.get())) {
    return false;
  }

  // Set the LSB to 1 and test rshift1 again.
  if (!BN_set_bit(lshift1.get(), 0) ||
      !BN_div(ret.get(), nullptr /* rem */, lshift1.get(), two.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "(LShift1 | 1) / 2", a.get(), ret.get()) ||
      !BN_rshift1(ret.get(), lshift1.get()) ||
      !ExpectBIGNUMsEqual(t, "(LShift | 1) >> 1", a.get(), ret.get())) {
    return false;
  }

  return true;
}

static bool TestLShift(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> a = GetBIGNUM(t, "A");
  bssl::UniquePtr<BIGNUM> lshift = GetBIGNUM(t, "LShift");
  int n = 0;
  if (!a || !lshift || !GetInt(t, &n, "N")) {
    return false;
  }

  bssl::UniquePtr<BIGNUM> ret(BN_new());
  if (!ret ||
      !BN_lshift(ret.get(), a.get(), n) ||
      !ExpectBIGNUMsEqual(t, "A << N", lshift.get(), ret.get()) ||
      !BN_rshift(ret.get(), lshift.get(), n) ||
      !ExpectBIGNUMsEqual(t, "A >> N", a.get(), ret.get())) {
    return false;
  }

  return true;
}

static bool TestRShift(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> a = GetBIGNUM(t, "A");
  bssl::UniquePtr<BIGNUM> rshift = GetBIGNUM(t, "RShift");
  int n = 0;
  if (!a || !rshift || !GetInt(t, &n, "N")) {
    return false;
  }

  bssl::UniquePtr<BIGNUM> ret(BN_new());
  if (!ret ||
      !BN_rshift(ret.get(), a.get(), n) ||
      !ExpectBIGNUMsEqual(t, "A >> N", rshift.get(), ret.get())) {
    return false;
  }

  return true;
}

static bool TestSquare(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> a = GetBIGNUM(t, "A");
  bssl::UniquePtr<BIGNUM> square = GetBIGNUM(t, "Square");
  bssl::UniquePtr<BIGNUM> zero(BN_new());
  if (!a || !square || !zero) {
    return false;
  }

  BN_zero(zero.get());

  bssl::UniquePtr<BIGNUM> ret(BN_new()), remainder(BN_new());
  if (!ret || !remainder ||
      !BN_sqr(ret.get(), a.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "A^2", square.get(), ret.get()) ||
      !BN_mul(ret.get(), a.get(), a.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "A * A", square.get(), ret.get()) ||
      !BN_div(ret.get(), remainder.get(), square.get(), a.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "Square / A", a.get(), ret.get()) ||
      !ExpectBIGNUMsEqual(t, "Square % A", zero.get(), remainder.get())) {
    return false;
  }

  BN_set_negative(a.get(), 0);
  if (!BN_sqrt(ret.get(), square.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "sqrt(Square)", a.get(), ret.get())) {
    return false;
  }

  // BN_sqrt should fail on non-squares and negative numbers.
  if (!BN_is_zero(square.get())) {
    bssl::UniquePtr<BIGNUM> tmp(BN_new());
    if (!tmp || !BN_copy(tmp.get(), square.get())) {
      return false;
    }
    BN_set_negative(tmp.get(), 1);

    if (BN_sqrt(ret.get(), tmp.get(), ctx)) {
      t->PrintLine("BN_sqrt succeeded on a negative number");
      return false;
    }
    ERR_clear_error();

    BN_set_negative(tmp.get(), 0);
    if (!BN_add(tmp.get(), tmp.get(), BN_value_one())) {
      return false;
    }
    if (BN_sqrt(ret.get(), tmp.get(), ctx)) {
      t->PrintLine("BN_sqrt succeeded on a non-square");
      return false;
    }
    ERR_clear_error();
  }

  return true;
}

static bool TestProduct(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> a = GetBIGNUM(t, "A");
  bssl::UniquePtr<BIGNUM> b = GetBIGNUM(t, "B");
  bssl::UniquePtr<BIGNUM> product = GetBIGNUM(t, "Product");
  bssl::UniquePtr<BIGNUM> zero(BN_new());
  if (!a || !b || !product || !zero) {
    return false;
  }

  BN_zero(zero.get());

  bssl::UniquePtr<BIGNUM> ret(BN_new()), remainder(BN_new());
  if (!ret || !remainder ||
      !BN_mul(ret.get(), a.get(), b.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "A * B", product.get(), ret.get()) ||
      !BN_div(ret.get(), remainder.get(), product.get(), a.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "Product / A", b.get(), ret.get()) ||
      !ExpectBIGNUMsEqual(t, "Product % A", zero.get(), remainder.get()) ||
      !BN_div(ret.get(), remainder.get(), product.get(), b.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "Product / B", a.get(), ret.get()) ||
      !ExpectBIGNUMsEqual(t, "Product % B", zero.get(), remainder.get())) {
    return false;
  }

  return true;
}

static bool TestQuotient(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> a = GetBIGNUM(t, "A");
  bssl::UniquePtr<BIGNUM> b = GetBIGNUM(t, "B");
  bssl::UniquePtr<BIGNUM> quotient = GetBIGNUM(t, "Quotient");
  bssl::UniquePtr<BIGNUM> remainder = GetBIGNUM(t, "Remainder");
  if (!a || !b || !quotient || !remainder) {
    return false;
  }

  bssl::UniquePtr<BIGNUM> ret(BN_new()), ret2(BN_new());
  if (!ret || !ret2 ||
      !BN_div(ret.get(), ret2.get(), a.get(), b.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "A / B", quotient.get(), ret.get()) ||
      !ExpectBIGNUMsEqual(t, "A % B", remainder.get(), ret2.get()) ||
      !BN_mul(ret.get(), quotient.get(), b.get(), ctx) ||
      !BN_add(ret.get(), ret.get(), remainder.get()) ||
      !ExpectBIGNUMsEqual(t, "Quotient * B + Remainder", a.get(), ret.get())) {
    return false;
  }

  // Test with |BN_mod_word| and |BN_div_word| if the divisor is small enough.
  BN_ULONG b_word = BN_get_word(b.get());
  if (!BN_is_negative(b.get()) && b_word != (BN_ULONG)-1) {
    BN_ULONG remainder_word = BN_get_word(remainder.get());
    assert(remainder_word != (BN_ULONG)-1);
    if (!BN_copy(ret.get(), a.get())) {
      return false;
    }
    BN_ULONG ret_word = BN_div_word(ret.get(), b_word);
    if (ret_word != remainder_word) {
      t->PrintLine("Got A %% B (word) = " BN_HEX_FMT1 ", wanted " BN_HEX_FMT1
                   "\n",
                   ret_word, remainder_word);
      return false;
    }
    if (!ExpectBIGNUMsEqual(t, "A / B (word)", quotient.get(), ret.get())) {
      return false;
    }

    ret_word = BN_mod_word(a.get(), b_word);
    if (ret_word != remainder_word) {
      t->PrintLine("Got A %% B (word) = " BN_HEX_FMT1 ", wanted " BN_HEX_FMT1
                   "\n",
                   ret_word, remainder_word);
      return false;
    }
  }

  // Test BN_nnmod.
  if (!BN_is_negative(b.get())) {
    bssl::UniquePtr<BIGNUM> nnmod(BN_new());
    if (!nnmod ||
        !BN_copy(nnmod.get(), remainder.get()) ||
        (BN_is_negative(nnmod.get()) &&
         !BN_add(nnmod.get(), nnmod.get(), b.get())) ||
        !BN_nnmod(ret.get(), a.get(), b.get(), ctx) ||
        !ExpectBIGNUMsEqual(t, "A % B (non-negative)", nnmod.get(),
                            ret.get())) {
      return false;
    }
  }

  return true;
}

static bool TestModMul(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> a = GetBIGNUM(t, "A");
  bssl::UniquePtr<BIGNUM> b = GetBIGNUM(t, "B");
  bssl::UniquePtr<BIGNUM> m = GetBIGNUM(t, "M");
  bssl::UniquePtr<BIGNUM> mod_mul = GetBIGNUM(t, "ModMul");
  if (!a || !b || !m || !mod_mul) {
    return false;
  }

  bssl::UniquePtr<BIGNUM> ret(BN_new());
  if (!ret ||
      !BN_mod_mul(ret.get(), a.get(), b.get(), m.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "A * B (mod M)", mod_mul.get(), ret.get())) {
    return false;
  }

  if (BN_is_odd(m.get())) {
    // Reduce |a| and |b| and test the Montgomery version.
    bssl::UniquePtr<BN_MONT_CTX> mont(BN_MONT_CTX_new());
    bssl::UniquePtr<BIGNUM> a_tmp(BN_new()), b_tmp(BN_new());
    if (!mont || !a_tmp || !b_tmp ||
        !BN_MONT_CTX_set(mont.get(), m.get(), ctx) ||
        !BN_nnmod(a_tmp.get(), a.get(), m.get(), ctx) ||
        !BN_nnmod(b_tmp.get(), b.get(), m.get(), ctx) ||
        !BN_to_montgomery(a_tmp.get(), a_tmp.get(), mont.get(), ctx) ||
        !BN_to_montgomery(b_tmp.get(), b_tmp.get(), mont.get(), ctx) ||
        !BN_mod_mul_montgomery(ret.get(), a_tmp.get(), b_tmp.get(), mont.get(),
                               ctx) ||
        !BN_from_montgomery(ret.get(), ret.get(), mont.get(), ctx) ||
        !ExpectBIGNUMsEqual(t, "A * B (mod M) (Montgomery)",
                            mod_mul.get(), ret.get())) {
      return false;
    }
  }

  return true;
}

static bool TestModSquare(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> a = GetBIGNUM(t, "A");
  bssl::UniquePtr<BIGNUM> m = GetBIGNUM(t, "M");
  bssl::UniquePtr<BIGNUM> mod_square = GetBIGNUM(t, "ModSquare");
  if (!a || !m || !mod_square) {
    return false;
  }

  bssl::UniquePtr<BIGNUM> a_copy(BN_new());
  bssl::UniquePtr<BIGNUM> ret(BN_new());
  if (!ret || !a_copy ||
      !BN_mod_mul(ret.get(), a.get(), a.get(), m.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "A * A (mod M)", mod_square.get(), ret.get()) ||
      // Repeat the operation with |a_copy|.
      !BN_copy(a_copy.get(), a.get()) ||
      !BN_mod_mul(ret.get(), a.get(), a_copy.get(), m.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "A * A_copy (mod M)", mod_square.get(),
                          ret.get())) {
    return false;
  }

  if (BN_is_odd(m.get())) {
    // Reduce |a| and test the Montgomery version.
    bssl::UniquePtr<BN_MONT_CTX> mont(BN_MONT_CTX_new());
    bssl::UniquePtr<BIGNUM> a_tmp(BN_new());
    if (!mont || !a_tmp ||
        !BN_MONT_CTX_set(mont.get(), m.get(), ctx) ||
        !BN_nnmod(a_tmp.get(), a.get(), m.get(), ctx) ||
        !BN_to_montgomery(a_tmp.get(), a_tmp.get(), mont.get(), ctx) ||
        !BN_mod_mul_montgomery(ret.get(), a_tmp.get(), a_tmp.get(), mont.get(),
                               ctx) ||
        !BN_from_montgomery(ret.get(), ret.get(), mont.get(), ctx) ||
        !ExpectBIGNUMsEqual(t, "A * A (mod M) (Montgomery)",
                            mod_square.get(), ret.get()) ||
        // Repeat the operation with |a_copy|.
        !BN_copy(a_copy.get(), a_tmp.get()) ||
        !BN_mod_mul_montgomery(ret.get(), a_tmp.get(), a_copy.get(), mont.get(),
                               ctx) ||
        !BN_from_montgomery(ret.get(), ret.get(), mont.get(), ctx) ||
        !ExpectBIGNUMsEqual(t, "A * A_copy (mod M) (Montgomery)",
                            mod_square.get(), ret.get())) {
      return false;
    }
  }

  return true;
}

static bool TestModExp(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> a = GetBIGNUM(t, "A");
  bssl::UniquePtr<BIGNUM> e = GetBIGNUM(t, "E");
  bssl::UniquePtr<BIGNUM> m = GetBIGNUM(t, "M");
  bssl::UniquePtr<BIGNUM> mod_exp = GetBIGNUM(t, "ModExp");
  if (!a || !e || !m || !mod_exp) {
    return false;
  }

  bssl::UniquePtr<BIGNUM> ret(BN_new());
  if (!ret ||
      !BN_mod_exp(ret.get(), a.get(), e.get(), m.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "A ^ E (mod M)", mod_exp.get(), ret.get())) {
    return false;
  }

  if (BN_is_odd(m.get())) {
    if (!BN_mod_exp_mont(ret.get(), a.get(), e.get(), m.get(), ctx, NULL) ||
        !ExpectBIGNUMsEqual(t, "A ^ E (mod M) (Montgomery)", mod_exp.get(),
                            ret.get()) ||
        !BN_mod_exp_mont_consttime(ret.get(), a.get(), e.get(), m.get(), ctx,
                                   NULL) ||
        !ExpectBIGNUMsEqual(t, "A ^ E (mod M) (constant-time)", mod_exp.get(),
                            ret.get())) {
      return false;
    }
  }

  return true;
}

static bool TestExp(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> a = GetBIGNUM(t, "A");
  bssl::UniquePtr<BIGNUM> e = GetBIGNUM(t, "E");
  bssl::UniquePtr<BIGNUM> exp = GetBIGNUM(t, "Exp");
  if (!a || !e || !exp) {
    return false;
  }

  bssl::UniquePtr<BIGNUM> ret(BN_new());
  if (!ret ||
      !BN_exp(ret.get(), a.get(), e.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "A ^ E", exp.get(), ret.get())) {
    return false;
  }

  return true;
}

static bool TestModSqrt(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> a = GetBIGNUM(t, "A");
  bssl::UniquePtr<BIGNUM> p = GetBIGNUM(t, "P");
  bssl::UniquePtr<BIGNUM> mod_sqrt = GetBIGNUM(t, "ModSqrt");
  bssl::UniquePtr<BIGNUM> mod_sqrt2(BN_new());
  if (!a || !p || !mod_sqrt || !mod_sqrt2 ||
      // There are two possible answers.
      !BN_sub(mod_sqrt2.get(), p.get(), mod_sqrt.get())) {
    return false;
  }

  // -0 is 0, not P.
  if (BN_is_zero(mod_sqrt.get())) {
    BN_zero(mod_sqrt2.get());
  }

  bssl::UniquePtr<BIGNUM> ret(BN_new());
  if (!ret ||
      !BN_mod_sqrt(ret.get(), a.get(), p.get(), ctx)) {
    return false;
  }

  if (BN_cmp(ret.get(), mod_sqrt2.get()) != 0 &&
      !ExpectBIGNUMsEqual(t, "sqrt(A) (mod P)", mod_sqrt.get(), ret.get())) {
    return false;
  }

  return true;
}

static bool TestNotModSquare(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> not_mod_square = GetBIGNUM(t, "NotModSquare");
  bssl::UniquePtr<BIGNUM> p = GetBIGNUM(t, "P");
  bssl::UniquePtr<BIGNUM> ret(BN_new());
  if (!not_mod_square || !p || !ret) {
    return false;
  }

  if (BN_mod_sqrt(ret.get(), not_mod_square.get(), p.get(), ctx)) {
    t->PrintLine("BN_mod_sqrt unexpectedly succeeded.");
    return false;
  }

  uint32_t err = ERR_peek_error();
  if (ERR_GET_LIB(err) == ERR_LIB_BN &&
      ERR_GET_REASON(err) == BN_R_NOT_A_SQUARE) {
    ERR_clear_error();
    return true;
  }

  return false;
}

static bool TestModInv(FileTest *t, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> a = GetBIGNUM(t, "A");
  bssl::UniquePtr<BIGNUM> m = GetBIGNUM(t, "M");
  bssl::UniquePtr<BIGNUM> mod_inv = GetBIGNUM(t, "ModInv");
  if (!a || !m || !mod_inv) {
    return false;
  }

  bssl::UniquePtr<BIGNUM> ret(BN_new());
  if (!ret ||
      !BN_mod_inverse(ret.get(), a.get(), m.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "inv(A) (mod M)", mod_inv.get(), ret.get())) {
    return false;
  }

  return true;
}

struct Test {
  const char *name;
  bool (*func)(FileTest *t, BN_CTX *ctx);
};

static const Test kTests[] = {
    {"Sum", TestSum},
    {"LShift1", TestLShift1},
    {"LShift", TestLShift},
    {"RShift", TestRShift},
    {"Square", TestSquare},
    {"Product", TestProduct},
    {"Quotient", TestQuotient},
    {"ModMul", TestModMul},
    {"ModSquare", TestModSquare},
    {"ModExp", TestModExp},
    {"Exp", TestExp},
    {"ModSqrt", TestModSqrt},
    {"NotModSquare", TestNotModSquare},
    {"ModInv", TestModInv},
};

static bool RunTest(FileTest *t, void *arg) {
  BN_CTX *ctx = reinterpret_cast<BN_CTX *>(arg);
  for (const Test &test : kTests) {
    if (t->GetType() != test.name) {
      continue;
    }
    return test.func(t, ctx);
  }
  t->PrintLine("Unknown test type: %s", t->GetType().c_str());
  return false;
}

static bool TestBN2BinPadded(BN_CTX *ctx) {
  uint8_t zeros[256], out[256], reference[128];

  OPENSSL_memset(zeros, 0, sizeof(zeros));

  // Test edge case at 0.
  bssl::UniquePtr<BIGNUM> n(BN_new());
  if (!n || !BN_bn2bin_padded(NULL, 0, n.get())) {
    fprintf(stderr,
            "BN_bn2bin_padded failed to encode 0 in an empty buffer.\n");
    return false;
  }
  OPENSSL_memset(out, -1, sizeof(out));
  if (!BN_bn2bin_padded(out, sizeof(out), n.get())) {
    fprintf(stderr,
            "BN_bn2bin_padded failed to encode 0 in a non-empty buffer.\n");
    return false;
  }
  if (OPENSSL_memcmp(zeros, out, sizeof(out))) {
    fprintf(stderr, "BN_bn2bin_padded did not zero buffer.\n");
    return false;
  }

  // Test a random numbers at various byte lengths.
  for (size_t bytes = 128 - 7; bytes <= 128; bytes++) {
    if (!BN_rand(n.get(), bytes * 8, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) {
      ERR_print_errors_fp(stderr);
      return false;
    }
    if (BN_num_bytes(n.get()) != bytes ||
        BN_bn2bin(n.get(), reference) != bytes) {
      fprintf(stderr, "Bad result from BN_rand; bytes.\n");
      return false;
    }
    // Empty buffer should fail.
    if (BN_bn2bin_padded(NULL, 0, n.get())) {
      fprintf(stderr,
              "BN_bn2bin_padded incorrectly succeeded on empty buffer.\n");
      return false;
    }
    // One byte short should fail.
    if (BN_bn2bin_padded(out, bytes - 1, n.get())) {
      fprintf(stderr, "BN_bn2bin_padded incorrectly succeeded on short.\n");
      return false;
    }
    // Exactly right size should encode.
    if (!BN_bn2bin_padded(out, bytes, n.get()) ||
        OPENSSL_memcmp(out, reference, bytes) != 0) {
      fprintf(stderr, "BN_bn2bin_padded gave a bad result.\n");
      return false;
    }
    // Pad up one byte extra.
    if (!BN_bn2bin_padded(out, bytes + 1, n.get()) ||
        OPENSSL_memcmp(out + 1, reference, bytes) ||
        OPENSSL_memcmp(out, zeros, 1)) {
      fprintf(stderr, "BN_bn2bin_padded gave a bad result.\n");
      return false;
    }
    // Pad up to 256.
    if (!BN_bn2bin_padded(out, sizeof(out), n.get()) ||
        OPENSSL_memcmp(out + sizeof(out) - bytes, reference, bytes) ||
        OPENSSL_memcmp(out, zeros, sizeof(out) - bytes)) {
      fprintf(stderr, "BN_bn2bin_padded gave a bad result.\n");
      return false;
    }
  }

  return true;
}

static bool TestLittleEndian() {
  bssl::UniquePtr<BIGNUM> x(BN_new());
  bssl::UniquePtr<BIGNUM> y(BN_new());
  if (!x || !y) {
    fprintf(stderr, "BN_new failed to malloc.\n");
    return false;
  }

  // Test edge case at 0. Fill |out| with garbage to ensure |BN_bn2le_padded|
  // wrote the result.
  uint8_t out[256], zeros[256];
  OPENSSL_memset(out, -1, sizeof(out));
  OPENSSL_memset(zeros, 0, sizeof(zeros));
  if (!BN_bn2le_padded(out, sizeof(out), x.get()) ||
      OPENSSL_memcmp(zeros, out, sizeof(out))) {
    fprintf(stderr, "BN_bn2le_padded failed to encode 0.\n");
    return false;
  }

  if (!BN_le2bn(out, sizeof(out), y.get()) ||
      BN_cmp(x.get(), y.get()) != 0) {
    fprintf(stderr, "BN_le2bn failed to decode 0 correctly.\n");
    return false;
  }

  // Test random numbers at various byte lengths.
  for (size_t bytes = 128 - 7; bytes <= 128; bytes++) {
    if (!BN_rand(x.get(), bytes * 8, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) {
      ERR_print_errors_fp(stderr);
      return false;
    }

    // Fill |out| with garbage to ensure |BN_bn2le_padded| wrote the result.
    OPENSSL_memset(out, -1, sizeof(out));
    if (!BN_bn2le_padded(out, sizeof(out), x.get())) {
      fprintf(stderr, "BN_bn2le_padded failed to encode random value.\n");
      return false;
    }

    // Compute the expected value by reversing the big-endian output.
    uint8_t expected[sizeof(out)];
    if (!BN_bn2bin_padded(expected, sizeof(expected), x.get())) {
      return false;
    }
    for (size_t i = 0; i < sizeof(expected) / 2; i++) {
      uint8_t tmp = expected[i];
      expected[i] = expected[sizeof(expected) - 1 - i];
      expected[sizeof(expected) - 1 - i] = tmp;
    }

    if (OPENSSL_memcmp(expected, out, sizeof(out))) {
      fprintf(stderr, "BN_bn2le_padded failed to encode value correctly.\n");
      hexdump(stderr, "Expected: ", expected, sizeof(expected));
      hexdump(stderr, "Got:      ", out, sizeof(out));
      return false;
    }

    // Make sure the decoding produces the same BIGNUM.
    if (!BN_le2bn(out, bytes, y.get()) ||
        BN_cmp(x.get(), y.get()) != 0) {
      bssl::UniquePtr<char> x_hex(BN_bn2hex(x.get())),
          y_hex(BN_bn2hex(y.get()));
      if (!x_hex || !y_hex) {
        return false;
      }
      fprintf(stderr, "BN_le2bn failed to decode value correctly.\n");
      fprintf(stderr, "Expected: %s\n", x_hex.get());
      hexdump(stderr, "Encoding: ", out, bytes);
      fprintf(stderr, "Got:      %s\n", y_hex.get());
      return false;
    }
  }

  return true;
}

static int DecimalToBIGNUM(bssl::UniquePtr<BIGNUM> *out, const char *in) {
  BIGNUM *raw = NULL;
  int ret = BN_dec2bn(&raw, in);
  out->reset(raw);
  return ret;
}

static bool TestDec2BN(BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> bn;
  int ret = DecimalToBIGNUM(&bn, "0");
  if (ret != 1 || !BN_is_zero(bn.get()) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_dec2bn gave a bad result.\n");
    return false;
  }

  ret = DecimalToBIGNUM(&bn, "256");
  if (ret != 3 || !BN_is_word(bn.get(), 256) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_dec2bn gave a bad result.\n");
    return false;
  }

  ret = DecimalToBIGNUM(&bn, "-42");
  if (ret != 3 || !BN_abs_is_word(bn.get(), 42) || !BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_dec2bn gave a bad result.\n");
    return false;
  }

  ret = DecimalToBIGNUM(&bn, "-0");
  if (ret != 2 || !BN_is_zero(bn.get()) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_dec2bn gave a bad result.\n");
    return false;
  }

  ret = DecimalToBIGNUM(&bn, "42trailing garbage is ignored");
  if (ret != 2 || !BN_abs_is_word(bn.get(), 42) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_dec2bn gave a bad result.\n");
    return false;
  }

  return true;
}

static bool TestHex2BN(BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> bn;
  int ret = HexToBIGNUM(&bn, "0");
  if (ret != 1 || !BN_is_zero(bn.get()) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_hex2bn gave a bad result.\n");
    return false;
  }

  ret = HexToBIGNUM(&bn, "256");
  if (ret != 3 || !BN_is_word(bn.get(), 0x256) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_hex2bn gave a bad result.\n");
    return false;
  }

  ret = HexToBIGNUM(&bn, "-42");
  if (ret != 3 || !BN_abs_is_word(bn.get(), 0x42) || !BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_hex2bn gave a bad result.\n");
    return false;
  }

  ret = HexToBIGNUM(&bn, "-0");
  if (ret != 2 || !BN_is_zero(bn.get()) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_hex2bn gave a bad result.\n");
    return false;
  }

  ret = HexToBIGNUM(&bn, "abctrailing garbage is ignored");
  if (ret != 3 || !BN_is_word(bn.get(), 0xabc) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_hex2bn gave a bad result.\n");
    return false;
  }

  return true;
}

static bssl::UniquePtr<BIGNUM> ASCIIToBIGNUM(const char *in) {
  BIGNUM *raw = NULL;
  if (!BN_asc2bn(&raw, in)) {
    return nullptr;
  }
  return bssl::UniquePtr<BIGNUM>(raw);
}

static bool TestASC2BN(BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> bn = ASCIIToBIGNUM("0");
  if (!bn || !BN_is_zero(bn.get()) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_asc2bn gave a bad result.\n");
    return false;
  }

  bn = ASCIIToBIGNUM("256");
  if (!bn || !BN_is_word(bn.get(), 256) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_asc2bn gave a bad result.\n");
    return false;
  }

  bn = ASCIIToBIGNUM("-42");
  if (!bn || !BN_abs_is_word(bn.get(), 42) || !BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_asc2bn gave a bad result.\n");
    return false;
  }

  bn = ASCIIToBIGNUM("0x1234");
  if (!bn || !BN_is_word(bn.get(), 0x1234) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_asc2bn gave a bad result.\n");
    return false;
  }

  bn = ASCIIToBIGNUM("0X1234");
  if (!bn || !BN_is_word(bn.get(), 0x1234) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_asc2bn gave a bad result.\n");
    return false;
  }

  bn = ASCIIToBIGNUM("-0xabcd");
  if (!bn || !BN_abs_is_word(bn.get(), 0xabcd) || !BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_asc2bn gave a bad result.\n");
    return false;
  }

  bn = ASCIIToBIGNUM("-0");
  if (!bn || !BN_is_zero(bn.get()) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_asc2bn gave a bad result.\n");
    return false;
  }

  bn = ASCIIToBIGNUM("123trailing garbage is ignored");
  if (!bn || !BN_is_word(bn.get(), 123) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_asc2bn gave a bad result.\n");
    return false;
  }

  return true;
}

struct MPITest {
  const char *base10;
  const char *mpi;
  size_t mpi_len;
};

static const MPITest kMPITests[] = {
  { "0", "\x00\x00\x00\x00", 4 },
  { "1", "\x00\x00\x00\x01\x01", 5 },
  { "-1", "\x00\x00\x00\x01\x81", 5 },
  { "128", "\x00\x00\x00\x02\x00\x80", 6 },
  { "256", "\x00\x00\x00\x02\x01\x00", 6 },
  { "-256", "\x00\x00\x00\x02\x81\x00", 6 },
};

static bool TestMPI() {
  uint8_t scratch[8];

  for (size_t i = 0; i < OPENSSL_ARRAY_SIZE(kMPITests); i++) {
    const MPITest &test = kMPITests[i];
    bssl::UniquePtr<BIGNUM> bn(ASCIIToBIGNUM(test.base10));
    if (!bn) {
      return false;
    }

    const size_t mpi_len = BN_bn2mpi(bn.get(), NULL);
    if (mpi_len > sizeof(scratch)) {
      fprintf(stderr, "MPI test #%u: MPI size is too large to test.\n",
              (unsigned)i);
      return false;
    }

    const size_t mpi_len2 = BN_bn2mpi(bn.get(), scratch);
    if (mpi_len != mpi_len2) {
      fprintf(stderr, "MPI test #%u: length changes.\n", (unsigned)i);
      return false;
    }

    if (mpi_len != test.mpi_len ||
        OPENSSL_memcmp(test.mpi, scratch, mpi_len) != 0) {
      fprintf(stderr, "MPI test #%u failed:\n", (unsigned)i);
      hexdump(stderr, "Expected: ", test.mpi, test.mpi_len);
      hexdump(stderr, "Got:      ", scratch, mpi_len);
      return false;
    }

    bssl::UniquePtr<BIGNUM> bn2(BN_mpi2bn(scratch, mpi_len, NULL));
    if (bn2.get() == nullptr) {
      fprintf(stderr, "MPI test #%u: failed to parse\n", (unsigned)i);
      return false;
    }

    if (BN_cmp(bn.get(), bn2.get()) != 0) {
      fprintf(stderr, "MPI test #%u: wrong result\n", (unsigned)i);
      return false;
    }
  }

  return true;
}

static bool TestRand() {
  bssl::UniquePtr<BIGNUM> bn(BN_new());
  if (!bn) {
    return false;
  }

  // Test BN_rand accounts for degenerate cases with |top| and |bottom|
  // parameters.
  if (!BN_rand(bn.get(), 0, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) ||
      !BN_is_zero(bn.get())) {
    fprintf(stderr, "BN_rand gave a bad result.\n");
    return false;
  }
  if (!BN_rand(bn.get(), 0, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ODD) ||
      !BN_is_zero(bn.get())) {
    fprintf(stderr, "BN_rand gave a bad result.\n");
    return false;
  }

  if (!BN_rand(bn.get(), 1, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) ||
      !BN_is_word(bn.get(), 1)) {
    fprintf(stderr, "BN_rand gave a bad result.\n");
    return false;
  }
  if (!BN_rand(bn.get(), 1, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY) ||
      !BN_is_word(bn.get(), 1)) {
    fprintf(stderr, "BN_rand gave a bad result.\n");
    return false;
  }
  if (!BN_rand(bn.get(), 1, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD) ||
      !BN_is_word(bn.get(), 1)) {
    fprintf(stderr, "BN_rand gave a bad result.\n");
    return false;
  }

  if (!BN_rand(bn.get(), 2, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY) ||
      !BN_is_word(bn.get(), 3)) {
    fprintf(stderr, "BN_rand gave a bad result.\n");
    return false;
  }

  return true;
}

static bool TestRandRange() {
  bssl::UniquePtr<BIGNUM> bn(BN_new()), six(BN_new());
  if (!bn || !six ||
      !BN_set_word(six.get(), 6)) {
    return false;
  }

  // Generate 1,000 random numbers and ensure they all stay in range. This check
  // may flakily pass when it should have failed but will not flakily fail.
  bool seen[6] = {false, false, false, false, false};
  for (unsigned i = 0; i < 1000; i++) {
    if (!BN_rand_range_ex(bn.get(), 1, six.get())) {
      return false;
    }

    BN_ULONG word = BN_get_word(bn.get());
    if (BN_is_negative(bn.get()) ||
        word < 1 ||
        word >= 6) {
      fprintf(stderr,
              "BN_rand_range_ex generated invalid value: " BN_DEC_FMT1 "\n",
              word);
      return false;
    }

    seen[word] = true;
  }

  // Test that all numbers were accounted for. Note this test is probabilistic
  // and may flakily fail when it should have passed. As an upper-bound on the
  // failure probability, we'll never see any one number with probability
  // (4/5)^1000, so the probability of failure is at most 5*(4/5)^1000. This is
  // around 1 in 2^320.
  for (unsigned i = 1; i < 6; i++) {
    if (!seen[i]) {
      fprintf(stderr, "BN_rand_range failed to generate %u.\n", i);
      return false;
    }
  }

  return true;
}

struct ASN1Test {
  const char *value_ascii;
  const char *der;
  size_t der_len;
};

static const ASN1Test kASN1Tests[] = {
    {"0", "\x02\x01\x00", 3},
    {"1", "\x02\x01\x01", 3},
    {"127", "\x02\x01\x7f", 3},
    {"128", "\x02\x02\x00\x80", 4},
    {"0xdeadbeef", "\x02\x05\x00\xde\xad\xbe\xef", 7},
    {"0x0102030405060708",
     "\x02\x08\x01\x02\x03\x04\x05\x06\x07\x08", 10},
    {"0xffffffffffffffff",
      "\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff", 11},
};

struct ASN1InvalidTest {
  const char *der;
  size_t der_len;
};

static const ASN1InvalidTest kASN1InvalidTests[] = {
    // Bad tag.
    {"\x03\x01\x00", 3},
    // Empty contents.
    {"\x02\x00", 2},
};

// kASN1BuggyTests contains incorrect encodings and the corresponding, expected
// results of |BN_parse_asn1_unsigned_buggy| given that input.
static const ASN1Test kASN1BuggyTests[] = {
    // Negative numbers.
    {"128", "\x02\x01\x80", 3},
    {"255", "\x02\x01\xff", 3},
    // Unnecessary leading zeros.
    {"1", "\x02\x02\x00\x01", 4},
};

static bool TestASN1() {
  for (const ASN1Test &test : kASN1Tests) {
    bssl::UniquePtr<BIGNUM> bn = ASCIIToBIGNUM(test.value_ascii);
    if (!bn) {
      return false;
    }

    // Test that the input is correctly parsed.
    bssl::UniquePtr<BIGNUM> bn2(BN_new());
    if (!bn2) {
      return false;
    }
    CBS cbs;
    CBS_init(&cbs, reinterpret_cast<const uint8_t*>(test.der), test.der_len);
    if (!BN_parse_asn1_unsigned(&cbs, bn2.get()) || CBS_len(&cbs) != 0) {
      fprintf(stderr, "Parsing ASN.1 INTEGER failed.\n");
      return false;
    }
    if (BN_cmp(bn.get(), bn2.get()) != 0) {
      fprintf(stderr, "Bad parse.\n");
      return false;
    }

    // Test the value serializes correctly.
    bssl::ScopedCBB cbb;
    uint8_t *der;
    size_t der_len;
    if (!CBB_init(cbb.get(), 0) ||
        !BN_marshal_asn1(cbb.get(), bn.get()) ||
        !CBB_finish(cbb.get(), &der, &der_len)) {
      return false;
    }
    bssl::UniquePtr<uint8_t> delete_der(der);
    if (der_len != test.der_len ||
        OPENSSL_memcmp(der, reinterpret_cast<const uint8_t *>(test.der),
                       der_len) != 0) {
      fprintf(stderr, "Bad serialization.\n");
      return false;
    }

    // |BN_parse_asn1_unsigned_buggy| parses all valid input.
    CBS_init(&cbs, reinterpret_cast<const uint8_t*>(test.der), test.der_len);
    if (!BN_parse_asn1_unsigned_buggy(&cbs, bn2.get()) || CBS_len(&cbs) != 0) {
      fprintf(stderr, "Parsing ASN.1 INTEGER failed.\n");
      return false;
    }
    if (BN_cmp(bn.get(), bn2.get()) != 0) {
      fprintf(stderr, "Bad parse.\n");
      return false;
    }
  }

  for (const ASN1InvalidTest &test : kASN1InvalidTests) {
    bssl::UniquePtr<BIGNUM> bn(BN_new());
    if (!bn) {
      return false;
    }
    CBS cbs;
    CBS_init(&cbs, reinterpret_cast<const uint8_t*>(test.der), test.der_len);
    if (BN_parse_asn1_unsigned(&cbs, bn.get())) {
      fprintf(stderr, "Parsed invalid input.\n");
      return false;
    }
    ERR_clear_error();

    // All tests in kASN1InvalidTests are also rejected by
    // |BN_parse_asn1_unsigned_buggy|.
    CBS_init(&cbs, reinterpret_cast<const uint8_t*>(test.der), test.der_len);
    if (BN_parse_asn1_unsigned_buggy(&cbs, bn.get())) {
      fprintf(stderr, "Parsed invalid input.\n");
      return false;
    }
    ERR_clear_error();
  }

  for (const ASN1Test &test : kASN1BuggyTests) {
    // These broken encodings are rejected by |BN_parse_asn1_unsigned|.
    bssl::UniquePtr<BIGNUM> bn(BN_new());
    if (!bn) {
      return false;
    }

    CBS cbs;
    CBS_init(&cbs, reinterpret_cast<const uint8_t*>(test.der), test.der_len);
    if (BN_parse_asn1_unsigned(&cbs, bn.get())) {
      fprintf(stderr, "Parsed invalid input.\n");
      return false;
    }
    ERR_clear_error();

    // However |BN_parse_asn1_unsigned_buggy| accepts them.
    bssl::UniquePtr<BIGNUM> bn2 = ASCIIToBIGNUM(test.value_ascii);
    if (!bn2) {
      return false;
    }

    CBS_init(&cbs, reinterpret_cast<const uint8_t*>(test.der), test.der_len);
    if (!BN_parse_asn1_unsigned_buggy(&cbs, bn.get()) || CBS_len(&cbs) != 0) {
      fprintf(stderr, "Parsing (invalid) ASN.1 INTEGER failed.\n");
      return false;
    }

    if (BN_cmp(bn.get(), bn2.get()) != 0) {
      fprintf(stderr, "\"Bad\" parse.\n");
      return false;
    }
  }

  // Serializing negative numbers is not supported.
  bssl::UniquePtr<BIGNUM> bn = ASCIIToBIGNUM("-1");
  if (!bn) {
    return false;
  }
  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), 0) ||
      BN_marshal_asn1(cbb.get(), bn.get())) {
    fprintf(stderr, "Serialized negative number.\n");
    return false;
  }
  ERR_clear_error();

  return true;
}

static bool TestNegativeZero(BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> a(BN_new());
  bssl::UniquePtr<BIGNUM> b(BN_new());
  bssl::UniquePtr<BIGNUM> c(BN_new());
  if (!a || !b || !c) {
    return false;
  }

  // Test that BN_mul never gives negative zero.
  if (!BN_set_word(a.get(), 1)) {
    return false;
  }
  BN_set_negative(a.get(), 1);
  BN_zero(b.get());
  if (!BN_mul(c.get(), a.get(), b.get(), ctx)) {
    return false;
  }
  if (!BN_is_zero(c.get()) || BN_is_negative(c.get())) {
    fprintf(stderr, "Multiplication test failed.\n");
    return false;
  }

  bssl::UniquePtr<BIGNUM> numerator(BN_new()), denominator(BN_new());
  if (!numerator || !denominator) {
    return false;
  }

  // Test that BN_div never gives negative zero in the quotient.
  if (!BN_set_word(numerator.get(), 1) ||
      !BN_set_word(denominator.get(), 2)) {
    return false;
  }
  BN_set_negative(numerator.get(), 1);
  if (!BN_div(a.get(), b.get(), numerator.get(), denominator.get(), ctx)) {
    return false;
  }
  if (!BN_is_zero(a.get()) || BN_is_negative(a.get())) {
    fprintf(stderr, "Incorrect quotient.\n");
    return false;
  }

  // Test that BN_div never gives negative zero in the remainder.
  if (!BN_set_word(denominator.get(), 1)) {
    return false;
  }
  if (!BN_div(a.get(), b.get(), numerator.get(), denominator.get(), ctx)) {
    return false;
  }
  if (!BN_is_zero(b.get()) || BN_is_negative(b.get())) {
    fprintf(stderr, "Incorrect remainder.\n");
    return false;
  }

  // Test that BN_set_negative will not produce a negative zero.
  BN_zero(a.get());
  BN_set_negative(a.get(), 1);
  if (BN_is_negative(a.get())) {
    fprintf(stderr, "BN_set_negative produced a negative zero.\n");
    return false;
  }

  // Test that forcibly creating a negative zero does not break |BN_bn2hex| or
  // |BN_bn2dec|.
  a->neg = 1;
  bssl::UniquePtr<char> dec(BN_bn2dec(a.get()));
  bssl::UniquePtr<char> hex(BN_bn2hex(a.get()));
  if (!dec || !hex ||
      strcmp(dec.get(), "-0") != 0 ||
      strcmp(hex.get(), "-0") != 0) {
    fprintf(stderr, "BN_bn2dec or BN_bn2hex failed with negative zero.\n");
    return false;
  }

  // Test that |BN_rshift| and |BN_rshift1| will not produce a negative zero.
  if (!BN_set_word(a.get(), 1)) {
    return false;
  }

  BN_set_negative(a.get(), 1);
  if (!BN_rshift(b.get(), a.get(), 1) ||
      !BN_rshift1(c.get(), a.get())) {
    return false;
  }

  if (!BN_is_zero(b.get()) || BN_is_negative(b.get())) {
    fprintf(stderr, "BN_rshift(-1, 1) produced the wrong result.\n");
    return false;
  }

  if (!BN_is_zero(c.get()) || BN_is_negative(c.get())) {
    fprintf(stderr, "BN_rshift1(-1) produced the wrong result.\n");
    return false;
  }

  // Test that |BN_div_word| will not produce a negative zero.
  if (BN_div_word(a.get(), 2) == (BN_ULONG)-1) {
    return false;
  }

  if (!BN_is_zero(a.get()) || BN_is_negative(a.get())) {
    fprintf(stderr, "BN_div_word(-1, 2) produced the wrong result.\n");
    return false;
  }

  return true;
}

static bool TestBadModulus(BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> a(BN_new());
  bssl::UniquePtr<BIGNUM> b(BN_new());
  bssl::UniquePtr<BIGNUM> zero(BN_new());
  bssl::UniquePtr<BN_MONT_CTX> mont(BN_MONT_CTX_new());
  if (!a || !b || !zero || !mont) {
    return false;
  }

  BN_zero(zero.get());

  if (BN_div(a.get(), b.get(), BN_value_one(), zero.get(), ctx)) {
    fprintf(stderr, "Division by zero unexpectedly succeeded.\n");
    return false;
  }
  ERR_clear_error();

  if (BN_mod_mul(a.get(), BN_value_one(), BN_value_one(), zero.get(), ctx)) {
    fprintf(stderr, "BN_mod_mul with zero modulus unexpectedly succeeded.\n");
    return false;
  }
  ERR_clear_error();

  if (BN_mod_exp(a.get(), BN_value_one(), BN_value_one(), zero.get(), ctx)) {
    fprintf(stderr, "BN_mod_exp with zero modulus unexpectedly succeeded.\n");
    return 0;
  }
  ERR_clear_error();

  if (BN_mod_exp_mont(a.get(), BN_value_one(), BN_value_one(), zero.get(), ctx,
                      NULL)) {
    fprintf(stderr,
            "BN_mod_exp_mont with zero modulus unexpectedly succeeded.\n");
    return 0;
  }
  ERR_clear_error();

  if (BN_mod_exp_mont_consttime(a.get(), BN_value_one(), BN_value_one(),
                                zero.get(), ctx, nullptr)) {
    fprintf(stderr,
            "BN_mod_exp_mont_consttime with zero modulus unexpectedly "
            "succeeded.\n");
    return 0;
  }
  ERR_clear_error();

  if (BN_MONT_CTX_set(mont.get(), zero.get(), ctx)) {
    fprintf(stderr,
            "BN_MONT_CTX_set unexpectedly succeeded for zero modulus.\n");
    return false;
  }
  ERR_clear_error();

  // Some operations also may not be used with an even modulus.

  if (!BN_set_word(b.get(), 16)) {
    return false;
  }

  if (BN_MONT_CTX_set(mont.get(), b.get(), ctx)) {
    fprintf(stderr,
            "BN_MONT_CTX_set unexpectedly succeeded for even modulus.\n");
    return false;
  }
  ERR_clear_error();

  if (BN_mod_exp_mont(a.get(), BN_value_one(), BN_value_one(), b.get(), ctx,
                      NULL)) {
    fprintf(stderr,
            "BN_mod_exp_mont with even modulus unexpectedly succeeded.\n");
    return 0;
  }
  ERR_clear_error();

  if (BN_mod_exp_mont_consttime(a.get(), BN_value_one(), BN_value_one(),
                                b.get(), ctx, nullptr)) {
    fprintf(stderr,
            "BN_mod_exp_mont_consttime with even modulus unexpectedly "
            "succeeded.\n");
    return 0;
  }
  ERR_clear_error();

  return true;
}

// TestExpModZero tests that 1**0 mod 1 == 0.
static bool TestExpModZero() {
  bssl::UniquePtr<BIGNUM> zero(BN_new()), a(BN_new()), r(BN_new());
  if (!zero || !a || !r ||
      !BN_rand(a.get(), 1024, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) {
    return false;
  }
  BN_zero(zero.get());

  if (!BN_mod_exp(r.get(), a.get(), zero.get(), BN_value_one(), nullptr) ||
      !BN_is_zero(r.get()) ||
      !BN_mod_exp_mont(r.get(), a.get(), zero.get(), BN_value_one(), nullptr,
                       nullptr) ||
      !BN_is_zero(r.get()) ||
      !BN_mod_exp_mont_consttime(r.get(), a.get(), zero.get(), BN_value_one(),
                                 nullptr, nullptr) ||
      !BN_is_zero(r.get()) ||
      !BN_mod_exp_mont_word(r.get(), 42, zero.get(), BN_value_one(), nullptr,
                            nullptr) ||
      !BN_is_zero(r.get())) {
    return false;
  }

  return true;
}

static bool TestSmallPrime(BN_CTX *ctx) {
  static const unsigned kBits = 10;

  bssl::UniquePtr<BIGNUM> r(BN_new());
  if (!r || !BN_generate_prime_ex(r.get(), static_cast<int>(kBits), 0, NULL,
                                  NULL, NULL)) {
    return false;
  }
  if (BN_num_bits(r.get()) != kBits) {
    fprintf(stderr, "Expected %u bit prime, got %u bit number\n", kBits,
            BN_num_bits(r.get()));
    return false;
  }

  return true;
}

static bool TestCmpWord() {
  static const BN_ULONG kMaxWord = (BN_ULONG)-1;

  bssl::UniquePtr<BIGNUM> r(BN_new());
  if (!r ||
      !BN_set_word(r.get(), 0)) {
    return false;
  }

  if (BN_cmp_word(r.get(), 0) != 0 ||
      BN_cmp_word(r.get(), 1) >= 0 ||
      BN_cmp_word(r.get(), kMaxWord) >= 0) {
    fprintf(stderr, "BN_cmp_word compared against 0 incorrectly.\n");
    return false;
  }

  if (!BN_set_word(r.get(), 100)) {
    return false;
  }

  if (BN_cmp_word(r.get(), 0) <= 0 ||
      BN_cmp_word(r.get(), 99) <= 0 ||
      BN_cmp_word(r.get(), 100) != 0 ||
      BN_cmp_word(r.get(), 101) >= 0 ||
      BN_cmp_word(r.get(), kMaxWord) >= 0) {
    fprintf(stderr, "BN_cmp_word compared against 100 incorrectly.\n");
    return false;
  }

  BN_set_negative(r.get(), 1);

  if (BN_cmp_word(r.get(), 0) >= 0 ||
      BN_cmp_word(r.get(), 100) >= 0 ||
      BN_cmp_word(r.get(), kMaxWord) >= 0) {
    fprintf(stderr, "BN_cmp_word compared against -100 incorrectly.\n");
    return false;
  }

  if (!BN_set_word(r.get(), kMaxWord)) {
    return false;
  }

  if (BN_cmp_word(r.get(), 0) <= 0 ||
      BN_cmp_word(r.get(), kMaxWord - 1) <= 0 ||
      BN_cmp_word(r.get(), kMaxWord) != 0) {
    fprintf(stderr, "BN_cmp_word compared against kMaxWord incorrectly.\n");
    return false;
  }

  if (!BN_add(r.get(), r.get(), BN_value_one())) {
    return false;
  }

  if (BN_cmp_word(r.get(), 0) <= 0 ||
      BN_cmp_word(r.get(), kMaxWord) <= 0) {
    fprintf(stderr, "BN_cmp_word compared against kMaxWord + 1 incorrectly.\n");
    return false;
  }

  BN_set_negative(r.get(), 1);

  if (BN_cmp_word(r.get(), 0) >= 0 ||
      BN_cmp_word(r.get(), kMaxWord) >= 0) {
    fprintf(stderr,
            "BN_cmp_word compared against -kMaxWord - 1 incorrectly.\n");
    return false;
  }

  return true;
}

static bool TestBN2Dec() {
  static const char *kBN2DecTests[] = {
      "0",
      "1",
      "-1",
      "100",
      "-100",
      "123456789012345678901234567890",
      "-123456789012345678901234567890",
      "123456789012345678901234567890123456789012345678901234567890",
      "-123456789012345678901234567890123456789012345678901234567890",
  };

  for (const char *test : kBN2DecTests) {
    bssl::UniquePtr<BIGNUM> bn;
    int ret = DecimalToBIGNUM(&bn, test);
    if (ret == 0) {
      return false;
    }

    bssl::UniquePtr<char> dec(BN_bn2dec(bn.get()));
    if (!dec) {
      fprintf(stderr, "BN_bn2dec failed on %s.\n", test);
      return false;
    }

    if (strcmp(dec.get(), test) != 0) {
      fprintf(stderr, "BN_bn2dec gave %s, wanted %s.\n", dec.get(), test);
      return false;
    }
  }

  return true;
}

static bool TestBNSetGetU64() {
  static const struct {
    const char *hex;
    uint64_t value;
  } kU64Tests[] = {
      {"0", UINT64_C(0x0)},
      {"1", UINT64_C(0x1)},
      {"ffffffff", UINT64_C(0xffffffff)},
      {"100000000", UINT64_C(0x100000000)},
      {"ffffffffffffffff", UINT64_C(0xffffffffffffffff)},
  };

  for (const auto& test : kU64Tests) {
    bssl::UniquePtr<BIGNUM> bn(BN_new()), expected;
    if (!bn ||
        !BN_set_u64(bn.get(), test.value) ||
        !HexToBIGNUM(&expected, test.hex) ||
        BN_cmp(bn.get(), expected.get()) != 0) {
      fprintf(stderr, "BN_set_u64 test failed for 0x%s.\n", test.hex);
      ERR_print_errors_fp(stderr);
      return false;
    }

    uint64_t tmp;
    if (!BN_get_u64(bn.get(), &tmp) || tmp != test.value) {
      fprintf(stderr, "BN_get_u64 test failed for 0x%s.\n", test.hex);
      return false;
    }

    BN_set_negative(bn.get(), 1);
    if (!BN_get_u64(bn.get(), &tmp) || tmp != test.value) {
      fprintf(stderr, "BN_get_u64 test failed for -0x%s.\n", test.hex);
      return false;
    }
  }

  // Test that BN_get_u64 fails on large numbers.
  bssl::UniquePtr<BIGNUM> bn(BN_new());
  if (!BN_lshift(bn.get(), BN_value_one(), 64)) {
    return false;
  }

  uint64_t tmp;
  if (BN_get_u64(bn.get(), &tmp)) {
    fprintf(stderr, "BN_get_u64 of 2^64 unexpectedly succeeded.\n");
    return false;
  }

  BN_set_negative(bn.get(), 1);
  if (BN_get_u64(bn.get(), &tmp)) {
    fprintf(stderr, "BN_get_u64 of -2^64 unexpectedly succeeded.\n");
    return false;
  }

  return true;
}

static bool TestBNPow2(BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM>
      power_of_two(BN_new()),
      random(BN_new()),
      expected(BN_new()),
      actual(BN_new());

  if (!power_of_two.get() ||
      !random.get() ||
      !expected.get() ||
      !actual.get()) {
    return false;
  }

  // Choose an exponent.
  for (size_t e = 3; e < 512; e += 11) {
    // Choose a bit length for our randoms.
    for (int len = 3; len < 512; len += 23) {
      // Set power_of_two = 2^e.
      if (!BN_lshift(power_of_two.get(), BN_value_one(), (int) e)) {
        fprintf(stderr, "Failed to shiftl.\n");
        return false;
      }

      // Test BN_is_pow2 on power_of_two.
      if (!BN_is_pow2(power_of_two.get())) {
        fprintf(stderr, "BN_is_pow2 returned false for a power of two.\n");
        hexdump(stderr, "Arg: ", power_of_two->d,
                power_of_two->top * sizeof(BN_ULONG));
        return false;
      }

      // Pick a large random value, ensuring it isn't a power of two.
      if (!BN_rand(random.get(), len, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY)) {
        fprintf(stderr, "Failed to generate random in TestBNPow2.\n");
        return false;
      }

      // Test BN_is_pow2 on |r|.
      if (BN_is_pow2(random.get())) {
        fprintf(stderr, "BN_is_pow2 returned true for a non-power of two.\n");
        hexdump(stderr, "Arg: ", random->d, random->top * sizeof(BN_ULONG));
        return false;
      }

      // Test BN_mod_pow2 on |r|.
      if (!BN_mod(expected.get(), random.get(), power_of_two.get(), ctx) ||
          !BN_mod_pow2(actual.get(), random.get(), e) ||
          BN_cmp(actual.get(), expected.get())) {
        fprintf(stderr, "BN_mod_pow2 returned the wrong value:\n");
        hexdump(stderr, "Expected: ", expected->d,
                expected->top * sizeof(BN_ULONG));
        hexdump(stderr, "Got:      ", actual->d,
                actual->top * sizeof(BN_ULONG));
        return false;
      }

      // Test BN_nnmod_pow2 on |r|.
      if (!BN_nnmod(expected.get(), random.get(), power_of_two.get(), ctx) ||
          !BN_nnmod_pow2(actual.get(), random.get(), e) ||
          BN_cmp(actual.get(), expected.get())) {
        fprintf(stderr, "BN_nnmod_pow2 failed on positive input:\n");
        hexdump(stderr, "Expected: ", expected->d,
                expected->top * sizeof(BN_ULONG));
        hexdump(stderr, "Got:      ", actual->d,
                actual->top * sizeof(BN_ULONG));
        return false;
      }

      // Test BN_nnmod_pow2 on -|r|.
      BN_set_negative(random.get(), 1);
      if (!BN_nnmod(expected.get(), random.get(), power_of_two.get(), ctx) ||
          !BN_nnmod_pow2(actual.get(), random.get(), e) ||
          BN_cmp(actual.get(), expected.get())) {
        fprintf(stderr, "BN_nnmod_pow2 failed on negative input:\n");
        hexdump(stderr, "Expected: ", expected->d,
                expected->top * sizeof(BN_ULONG));
        hexdump(stderr, "Got:      ", actual->d,
                actual->top * sizeof(BN_ULONG));
        return false;
      }
    }
  }

  return true;
}

static const int kPrimes[4096] = {
    2,     3,     5,     7,     11,    13,    17,    19,    23,    29,    31,
    37,    41,    43,    47,    53,    59,    61,    67,    71,    73,    79,
    83,    89,    97,    101,   103,   107,   109,   113,   127,   131,   137,
    139,   149,   151,   157,   163,   167,   173,   179,   181,   191,   193,
    197,   199,   211,   223,   227,   229,   233,   239,   241,   251,   257,
    263,   269,   271,   277,   281,   283,   293,   307,   311,   313,   317,
    331,   337,   347,   349,   353,   359,   367,   373,   379,   383,   389,
    397,   401,   409,   419,   421,   431,   433,   439,   443,   449,   457,
    461,   463,   467,   479,   487,   491,   499,   503,   509,   521,   523,
    541,   547,   557,   563,   569,   571,   577,   587,   593,   599,   601,
    607,   613,   617,   619,   631,   641,   643,   647,   653,   659,   661,
    673,   677,   683,   691,   701,   709,   719,   727,   733,   739,   743,
    751,   757,   761,   769,   773,   787,   797,   809,   811,   821,   823,
    827,   829,   839,   853,   857,   859,   863,   877,   881,   883,   887,
    907,   911,   919,   929,   937,   941,   947,   953,   967,   971,   977,
    983,   991,   997,   1009,  1013,  1019,  1021,  1031,  1033,  1039,  1049,
    1051,  1061,  1063,  1069,  1087,  1091,  1093,  1097,  1103,  1109,  1117,
    1123,  1129,  1151,  1153,  1163,  1171,  1181,  1187,  1193,  1201,  1213,
    1217,  1223,  1229,  1231,  1237,  1249,  1259,  1277,  1279,  1283,  1289,
    1291,  1297,  1301,  1303,  1307,  1319,  1321,  1327,  1361,  1367,  1373,
    1381,  1399,  1409,  1423,  1427,  1429,  1433,  1439,  1447,  1451,  1453,
    1459,  1471,  1481,  1483,  1487,  1489,  1493,  1499,  1511,  1523,  1531,
    1543,  1549,  1553,  1559,  1567,  1571,  1579,  1583,  1597,  1601,  1607,
    1609,  1613,  1619,  1621,  1627,  1637,  1657,  1663,  1667,  1669,  1693,
    1697,  1699,  1709,  1721,  1723,  1733,  1741,  1747,  1753,  1759,  1777,
    1783,  1787,  1789,  1801,  1811,  1823,  1831,  1847,  1861,  1867,  1871,
    1873,  1877,  1879,  1889,  1901,  1907,  1913,  1931,  1933,  1949,  1951,
    1973,  1979,  1987,  1993,  1997,  1999,  2003,  2011,  2017,  2027,  2029,
    2039,  2053,  2063,  2069,  2081,  2083,  2087,  2089,  2099,  2111,  2113,
    2129,  2131,  2137,  2141,  2143,  2153,  2161,  2179,  2203,  2207,  2213,
    2221,  2237,  2239,  2243,  2251,  2267,  2269,  2273,  2281,  2287,  2293,
    2297,  2309,  2311,  2333,  2339,  2341,  2347,  2351,  2357,  2371,  2377,
    2381,  2383,  2389,  2393,  2399,  2411,  2417,  2423,  2437,  2441,  2447,
    2459,  2467,  2473,  2477,  2503,  2521,  2531,  2539,  2543,  2549,  2551,
    2557,  2579,  2591,  2593,  2609,  2617,  2621,  2633,  2647,  2657,  2659,
    2663,  2671,  2677,  2683,  2687,  2689,  2693,  2699,  2707,  2711,  2713,
    2719,  2729,  2731,  2741,  2749,  2753,  2767,  2777,  2789,  2791,  2797,
    2801,  2803,  2819,  2833,  2837,  2843,  2851,  2857,  2861,  2879,  2887,
    2897,  2903,  2909,  2917,  2927,  2939,  2953,  2957,  2963,  2969,  2971,
    2999,  3001,  3011,  3019,  3023,  3037,  3041,  3049,  3061,  3067,  3079,
    3083,  3089,  3109,  3119,  3121,  3137,  3163,  3167,  3169,  3181,  3187,
    3191,  3203,  3209,  3217,  3221,  3229,  3251,  3253,  3257,  3259,  3271,
    3299,  3301,  3307,  3313,  3319,  3323,  3329,  3331,  3343,  3347,  3359,
    3361,  3371,  3373,  3389,  3391,  3407,  3413,  3433,  3449,  3457,  3461,
    3463,  3467,  3469,  3491,  3499,  3511,  3517,  3527,  3529,  3533,  3539,
    3541,  3547,  3557,  3559,  3571,  3581,  3583,  3593,  3607,  3613,  3617,
    3623,  3631,  3637,  3643,  3659,  3671,  3673,  3677,  3691,  3697,  3701,
    3709,  3719,  3727,  3733,  3739,  3761,  3767,  3769,  3779,  3793,  3797,
    3803,  3821,  3823,  3833,  3847,  3851,  3853,  3863,  3877,  3881,  3889,
    3907,  3911,  3917,  3919,  3923,  3929,  3931,  3943,  3947,  3967,  3989,
    4001,  4003,  4007,  4013,  4019,  4021,  4027,  4049,  4051,  4057,  4073,
    4079,  4091,  4093,  4099,  4111,  4127,  4129,  4133,  4139,  4153,  4157,
    4159,  4177,  4201,  4211,  4217,  4219,  4229,  4231,  4241,  4243,  4253,
    4259,  4261,  4271,  4273,  4283,  4289,  4297,  4327,  4337,  4339,  4349,
    4357,  4363,  4373,  4391,  4397,  4409,  4421,  4423,  4441,  4447,  4451,
    4457,  4463,  4481,  4483,  4493,  4507,  4513,  4517,  4519,  4523,  4547,
    4549,  4561,  4567,  4583,  4591,  4597,  4603,  4621,  4637,  4639,  4643,
    4649,  4651,  4657,  4663,  4673,  4679,  4691,  4703,  4721,  4723,  4729,
    4733,  4751,  4759,  4783,  4787,  4789,  4793,  4799,  4801,  4813,  4817,
    4831,  4861,  4871,  4877,  4889,  4903,  4909,  4919,  4931,  4933,  4937,
    4943,  4951,  4957,  4967,  4969,  4973,  4987,  4993,  4999,  5003,  5009,
    5011,  5021,  5023,  5039,  5051,  5059,  5077,  5081,  5087,  5099,  5101,
    5107,  5113,  5119,  5147,  5153,  5167,  5171,  5179,  5189,  5197,  5209,
    5227,  5231,  5233,  5237,  5261,  5273,  5279,  5281,  5297,  5303,  5309,
    5323,  5333,  5347,  5351,  5381,  5387,  5393,  5399,  5407,  5413,  5417,
    5419,  5431,  5437,  5441,  5443,  5449,  5471,  5477,  5479,  5483,  5501,
    5503,  5507,  5519,  5521,  5527,  5531,  5557,  5563,  5569,  5573,  5581,
    5591,  5623,  5639,  5641,  5647,  5651,  5653,  5657,  5659,  5669,  5683,
    5689,  5693,  5701,  5711,  5717,  5737,  5741,  5743,  5749,  5779,  5783,
    5791,  5801,  5807,  5813,  5821,  5827,  5839,  5843,  5849,  5851,  5857,
    5861,  5867,  5869,  5879,  5881,  5897,  5903,  5923,  5927,  5939,  5953,
    5981,  5987,  6007,  6011,  6029,  6037,  6043,  6047,  6053,  6067,  6073,
    6079,  6089,  6091,  6101,  6113,  6121,  6131,  6133,  6143,  6151,  6163,
    6173,  6197,  6199,  6203,  6211,  6217,  6221,  6229,  6247,  6257,  6263,
    6269,  6271,  6277,  6287,  6299,  6301,  6311,  6317,  6323,  6329,  6337,
    6343,  6353,  6359,  6361,  6367,  6373,  6379,  6389,  6397,  6421,  6427,
    6449,  6451,  6469,  6473,  6481,  6491,  6521,  6529,  6547,  6551,  6553,
    6563,  6569,  6571,  6577,  6581,  6599,  6607,  6619,  6637,  6653,  6659,
    6661,  6673,  6679,  6689,  6691,  6701,  6703,  6709,  6719,  6733,  6737,
    6761,  6763,  6779,  6781,  6791,  6793,  6803,  6823,  6827,  6829,  6833,
    6841,  6857,  6863,  6869,  6871,  6883,  6899,  6907,  6911,  6917,  6947,
    6949,  6959,  6961,  6967,  6971,  6977,  6983,  6991,  6997,  7001,  7013,
    7019,  7027,  7039,  7043,  7057,  7069,  7079,  7103,  7109,  7121,  7127,
    7129,  7151,  7159,  7177,  7187,  7193,  7207,  7211,  7213,  7219,  7229,
    7237,  7243,  7247,  7253,  7283,  7297,  7307,  7309,  7321,  7331,  7333,
    7349,  7351,  7369,  7393,  7411,  7417,  7433,  7451,  7457,  7459,  7477,
    7481,  7487,  7489,  7499,  7507,  7517,  7523,  7529,  7537,  7541,  7547,
    7549,  7559,  7561,  7573,  7577,  7583,  7589,  7591,  7603,  7607,  7621,
    7639,  7643,  7649,  7669,  7673,  7681,  7687,  7691,  7699,  7703,  7717,
    7723,  7727,  7741,  7753,  7757,  7759,  7789,  7793,  7817,  7823,  7829,
    7841,  7853,  7867,  7873,  7877,  7879,  7883,  7901,  7907,  7919,  7927,
    7933,  7937,  7949,  7951,  7963,  7993,  8009,  8011,  8017,  8039,  8053,
    8059,  8069,  8081,  8087,  8089,  8093,  8101,  8111,  8117,  8123,  8147,
    8161,  8167,  8171,  8179,  8191,  8209,  8219,  8221,  8231,  8233,  8237,
    8243,  8263,  8269,  8273,  8287,  8291,  8293,  8297,  8311,  8317,  8329,
    8353,  8363,  8369,  8377,  8387,  8389,  8419,  8423,  8429,  8431,  8443,
    8447,  8461,  8467,  8501,  8513,  8521,  8527,  8537,  8539,  8543,  8563,
    8573,  8581,  8597,  8599,  8609,  8623,  8627,  8629,  8641,  8647,  8663,
    8669,  8677,  8681,  8689,  8693,  8699,  8707,  8713,  8719,  8731,  8737,
    8741,  8747,  8753,  8761,  8779,  8783,  8803,  8807,  8819,  8821,  8831,
    8837,  8839,  8849,  8861,  8863,  8867,  8887,  8893,  8923,  8929,  8933,
    8941,  8951,  8963,  8969,  8971,  8999,  9001,  9007,  9011,  9013,  9029,
    9041,  9043,  9049,  9059,  9067,  9091,  9103,  9109,  9127,  9133,  9137,
    9151,  9157,  9161,  9173,  9181,  9187,  9199,  9203,  9209,  9221,  9227,
    9239,  9241,  9257,  9277,  9281,  9283,  9293,  9311,  9319,  9323,  9337,
    9341,  9343,  9349,  9371,  9377,  9391,  9397,  9403,  9413,  9419,  9421,
    9431,  9433,  9437,  9439,  9461,  9463,  9467,  9473,  9479,  9491,  9497,
    9511,  9521,  9533,  9539,  9547,  9551,  9587,  9601,  9613,  9619,  9623,
    9629,  9631,  9643,  9649,  9661,  9677,  9679,  9689,  9697,  9719,  9721,
    9733,  9739,  9743,  9749,  9767,  9769,  9781,  9787,  9791,  9803,  9811,
    9817,  9829,  9833,  9839,  9851,  9857,  9859,  9871,  9883,  9887,  9901,
    9907,  9923,  9929,  9931,  9941,  9949,  9967,  9973,  10007, 10009, 10037,
    10039, 10061, 10067, 10069, 10079, 10091, 10093, 10099, 10103, 10111, 10133,
    10139, 10141, 10151, 10159, 10163, 10169, 10177, 10181, 10193, 10211, 10223,
    10243, 10247, 10253, 10259, 10267, 10271, 10273, 10289, 10301, 10303, 10313,
    10321, 10331, 10333, 10337, 10343, 10357, 10369, 10391, 10399, 10427, 10429,
    10433, 10453, 10457, 10459, 10463, 10477, 10487, 10499, 10501, 10513, 10529,
    10531, 10559, 10567, 10589, 10597, 10601, 10607, 10613, 10627, 10631, 10639,
    10651, 10657, 10663, 10667, 10687, 10691, 10709, 10711, 10723, 10729, 10733,
    10739, 10753, 10771, 10781, 10789, 10799, 10831, 10837, 10847, 10853, 10859,
    10861, 10867, 10883, 10889, 10891, 10903, 10909, 10937, 10939, 10949, 10957,
    10973, 10979, 10987, 10993, 11003, 11027, 11047, 11057, 11059, 11069, 11071,
    11083, 11087, 11093, 11113, 11117, 11119, 11131, 11149, 11159, 11161, 11171,
    11173, 11177, 11197, 11213, 11239, 11243, 11251, 11257, 11261, 11273, 11279,
    11287, 11299, 11311, 11317, 11321, 11329, 11351, 11353, 11369, 11383, 11393,
    11399, 11411, 11423, 11437, 11443, 11447, 11467, 11471, 11483, 11489, 11491,
    11497, 11503, 11519, 11527, 11549, 11551, 11579, 11587, 11593, 11597, 11617,
    11621, 11633, 11657, 11677, 11681, 11689, 11699, 11701, 11717, 11719, 11731,
    11743, 11777, 11779, 11783, 11789, 11801, 11807, 11813, 11821, 11827, 11831,
    11833, 11839, 11863, 11867, 11887, 11897, 11903, 11909, 11923, 11927, 11933,
    11939, 11941, 11953, 11959, 11969, 11971, 11981, 11987, 12007, 12011, 12037,
    12041, 12043, 12049, 12071, 12073, 12097, 12101, 12107, 12109, 12113, 12119,
    12143, 12149, 12157, 12161, 12163, 12197, 12203, 12211, 12227, 12239, 12241,
    12251, 12253, 12263, 12269, 12277, 12281, 12289, 12301, 12323, 12329, 12343,
    12347, 12373, 12377, 12379, 12391, 12401, 12409, 12413, 12421, 12433, 12437,
    12451, 12457, 12473, 12479, 12487, 12491, 12497, 12503, 12511, 12517, 12527,
    12539, 12541, 12547, 12553, 12569, 12577, 12583, 12589, 12601, 12611, 12613,
    12619, 12637, 12641, 12647, 12653, 12659, 12671, 12689, 12697, 12703, 12713,
    12721, 12739, 12743, 12757, 12763, 12781, 12791, 12799, 12809, 12821, 12823,
    12829, 12841, 12853, 12889, 12893, 12899, 12907, 12911, 12917, 12919, 12923,
    12941, 12953, 12959, 12967, 12973, 12979, 12983, 13001, 13003, 13007, 13009,
    13033, 13037, 13043, 13049, 13063, 13093, 13099, 13103, 13109, 13121, 13127,
    13147, 13151, 13159, 13163, 13171, 13177, 13183, 13187, 13217, 13219, 13229,
    13241, 13249, 13259, 13267, 13291, 13297, 13309, 13313, 13327, 13331, 13337,
    13339, 13367, 13381, 13397, 13399, 13411, 13417, 13421, 13441, 13451, 13457,
    13463, 13469, 13477, 13487, 13499, 13513, 13523, 13537, 13553, 13567, 13577,
    13591, 13597, 13613, 13619, 13627, 13633, 13649, 13669, 13679, 13681, 13687,
    13691, 13693, 13697, 13709, 13711, 13721, 13723, 13729, 13751, 13757, 13759,
    13763, 13781, 13789, 13799, 13807, 13829, 13831, 13841, 13859, 13873, 13877,
    13879, 13883, 13901, 13903, 13907, 13913, 13921, 13931, 13933, 13963, 13967,
    13997, 13999, 14009, 14011, 14029, 14033, 14051, 14057, 14071, 14081, 14083,
    14087, 14107, 14143, 14149, 14153, 14159, 14173, 14177, 14197, 14207, 14221,
    14243, 14249, 14251, 14281, 14293, 14303, 14321, 14323, 14327, 14341, 14347,
    14369, 14387, 14389, 14401, 14407, 14411, 14419, 14423, 14431, 14437, 14447,
    14449, 14461, 14479, 14489, 14503, 14519, 14533, 14537, 14543, 14549, 14551,
    14557, 14561, 14563, 14591, 14593, 14621, 14627, 14629, 14633, 14639, 14653,
    14657, 14669, 14683, 14699, 14713, 14717, 14723, 14731, 14737, 14741, 14747,
    14753, 14759, 14767, 14771, 14779, 14783, 14797, 14813, 14821, 14827, 14831,
    14843, 14851, 14867, 14869, 14879, 14887, 14891, 14897, 14923, 14929, 14939,
    14947, 14951, 14957, 14969, 14983, 15013, 15017, 15031, 15053, 15061, 15073,
    15077, 15083, 15091, 15101, 15107, 15121, 15131, 15137, 15139, 15149, 15161,
    15173, 15187, 15193, 15199, 15217, 15227, 15233, 15241, 15259, 15263, 15269,
    15271, 15277, 15287, 15289, 15299, 15307, 15313, 15319, 15329, 15331, 15349,
    15359, 15361, 15373, 15377, 15383, 15391, 15401, 15413, 15427, 15439, 15443,
    15451, 15461, 15467, 15473, 15493, 15497, 15511, 15527, 15541, 15551, 15559,
    15569, 15581, 15583, 15601, 15607, 15619, 15629, 15641, 15643, 15647, 15649,
    15661, 15667, 15671, 15679, 15683, 15727, 15731, 15733, 15737, 15739, 15749,
    15761, 15767, 15773, 15787, 15791, 15797, 15803, 15809, 15817, 15823, 15859,
    15877, 15881, 15887, 15889, 15901, 15907, 15913, 15919, 15923, 15937, 15959,
    15971, 15973, 15991, 16001, 16007, 16033, 16057, 16061, 16063, 16067, 16069,
    16073, 16087, 16091, 16097, 16103, 16111, 16127, 16139, 16141, 16183, 16187,
    16189, 16193, 16217, 16223, 16229, 16231, 16249, 16253, 16267, 16273, 16301,
    16319, 16333, 16339, 16349, 16361, 16363, 16369, 16381, 16411, 16417, 16421,
    16427, 16433, 16447, 16451, 16453, 16477, 16481, 16487, 16493, 16519, 16529,
    16547, 16553, 16561, 16567, 16573, 16603, 16607, 16619, 16631, 16633, 16649,
    16651, 16657, 16661, 16673, 16691, 16693, 16699, 16703, 16729, 16741, 16747,
    16759, 16763, 16787, 16811, 16823, 16829, 16831, 16843, 16871, 16879, 16883,
    16889, 16901, 16903, 16921, 16927, 16931, 16937, 16943, 16963, 16979, 16981,
    16987, 16993, 17011, 17021, 17027, 17029, 17033, 17041, 17047, 17053, 17077,
    17093, 17099, 17107, 17117, 17123, 17137, 17159, 17167, 17183, 17189, 17191,
    17203, 17207, 17209, 17231, 17239, 17257, 17291, 17293, 17299, 17317, 17321,
    17327, 17333, 17341, 17351, 17359, 17377, 17383, 17387, 17389, 17393, 17401,
    17417, 17419, 17431, 17443, 17449, 17467, 17471, 17477, 17483, 17489, 17491,
    17497, 17509, 17519, 17539, 17551, 17569, 17573, 17579, 17581, 17597, 17599,
    17609, 17623, 17627, 17657, 17659, 17669, 17681, 17683, 17707, 17713, 17729,
    17737, 17747, 17749, 17761, 17783, 17789, 17791, 17807, 17827, 17837, 17839,
    17851, 17863, 17881, 17891, 17903, 17909, 17911, 17921, 17923, 17929, 17939,
    17957, 17959, 17971, 17977, 17981, 17987, 17989, 18013, 18041, 18043, 18047,
    18049, 18059, 18061, 18077, 18089, 18097, 18119, 18121, 18127, 18131, 18133,
    18143, 18149, 18169, 18181, 18191, 18199, 18211, 18217, 18223, 18229, 18233,
    18251, 18253, 18257, 18269, 18287, 18289, 18301, 18307, 18311, 18313, 18329,
    18341, 18353, 18367, 18371, 18379, 18397, 18401, 18413, 18427, 18433, 18439,
    18443, 18451, 18457, 18461, 18481, 18493, 18503, 18517, 18521, 18523, 18539,
    18541, 18553, 18583, 18587, 18593, 18617, 18637, 18661, 18671, 18679, 18691,
    18701, 18713, 18719, 18731, 18743, 18749, 18757, 18773, 18787, 18793, 18797,
    18803, 18839, 18859, 18869, 18899, 18911, 18913, 18917, 18919, 18947, 18959,
    18973, 18979, 19001, 19009, 19013, 19031, 19037, 19051, 19069, 19073, 19079,
    19081, 19087, 19121, 19139, 19141, 19157, 19163, 19181, 19183, 19207, 19211,
    19213, 19219, 19231, 19237, 19249, 19259, 19267, 19273, 19289, 19301, 19309,
    19319, 19333, 19373, 19379, 19381, 19387, 19391, 19403, 19417, 19421, 19423,
    19427, 19429, 19433, 19441, 19447, 19457, 19463, 19469, 19471, 19477, 19483,
    19489, 19501, 19507, 19531, 19541, 19543, 19553, 19559, 19571, 19577, 19583,
    19597, 19603, 19609, 19661, 19681, 19687, 19697, 19699, 19709, 19717, 19727,
    19739, 19751, 19753, 19759, 19763, 19777, 19793, 19801, 19813, 19819, 19841,
    19843, 19853, 19861, 19867, 19889, 19891, 19913, 19919, 19927, 19937, 19949,
    19961, 19963, 19973, 19979, 19991, 19993, 19997, 20011, 20021, 20023, 20029,
    20047, 20051, 20063, 20071, 20089, 20101, 20107, 20113, 20117, 20123, 20129,
    20143, 20147, 20149, 20161, 20173, 20177, 20183, 20201, 20219, 20231, 20233,
    20249, 20261, 20269, 20287, 20297, 20323, 20327, 20333, 20341, 20347, 20353,
    20357, 20359, 20369, 20389, 20393, 20399, 20407, 20411, 20431, 20441, 20443,
    20477, 20479, 20483, 20507, 20509, 20521, 20533, 20543, 20549, 20551, 20563,
    20593, 20599, 20611, 20627, 20639, 20641, 20663, 20681, 20693, 20707, 20717,
    20719, 20731, 20743, 20747, 20749, 20753, 20759, 20771, 20773, 20789, 20807,
    20809, 20849, 20857, 20873, 20879, 20887, 20897, 20899, 20903, 20921, 20929,
    20939, 20947, 20959, 20963, 20981, 20983, 21001, 21011, 21013, 21017, 21019,
    21023, 21031, 21059, 21061, 21067, 21089, 21101, 21107, 21121, 21139, 21143,
    21149, 21157, 21163, 21169, 21179, 21187, 21191, 21193, 21211, 21221, 21227,
    21247, 21269, 21277, 21283, 21313, 21317, 21319, 21323, 21341, 21347, 21377,
    21379, 21383, 21391, 21397, 21401, 21407, 21419, 21433, 21467, 21481, 21487,
    21491, 21493, 21499, 21503, 21517, 21521, 21523, 21529, 21557, 21559, 21563,
    21569, 21577, 21587, 21589, 21599, 21601, 21611, 21613, 21617, 21647, 21649,
    21661, 21673, 21683, 21701, 21713, 21727, 21737, 21739, 21751, 21757, 21767,
    21773, 21787, 21799, 21803, 21817, 21821, 21839, 21841, 21851, 21859, 21863,
    21871, 21881, 21893, 21911, 21929, 21937, 21943, 21961, 21977, 21991, 21997,
    22003, 22013, 22027, 22031, 22037, 22039, 22051, 22063, 22067, 22073, 22079,
    22091, 22093, 22109, 22111, 22123, 22129, 22133, 22147, 22153, 22157, 22159,
    22171, 22189, 22193, 22229, 22247, 22259, 22271, 22273, 22277, 22279, 22283,
    22291, 22303, 22307, 22343, 22349, 22367, 22369, 22381, 22391, 22397, 22409,
    22433, 22441, 22447, 22453, 22469, 22481, 22483, 22501, 22511, 22531, 22541,
    22543, 22549, 22567, 22571, 22573, 22613, 22619, 22621, 22637, 22639, 22643,
    22651, 22669, 22679, 22691, 22697, 22699, 22709, 22717, 22721, 22727, 22739,
    22741, 22751, 22769, 22777, 22783, 22787, 22807, 22811, 22817, 22853, 22859,
    22861, 22871, 22877, 22901, 22907, 22921, 22937, 22943, 22961, 22963, 22973,
    22993, 23003, 23011, 23017, 23021, 23027, 23029, 23039, 23041, 23053, 23057,
    23059, 23063, 23071, 23081, 23087, 23099, 23117, 23131, 23143, 23159, 23167,
    23173, 23189, 23197, 23201, 23203, 23209, 23227, 23251, 23269, 23279, 23291,
    23293, 23297, 23311, 23321, 23327, 23333, 23339, 23357, 23369, 23371, 23399,
    23417, 23431, 23447, 23459, 23473, 23497, 23509, 23531, 23537, 23539, 23549,
    23557, 23561, 23563, 23567, 23581, 23593, 23599, 23603, 23609, 23623, 23627,
    23629, 23633, 23663, 23669, 23671, 23677, 23687, 23689, 23719, 23741, 23743,
    23747, 23753, 23761, 23767, 23773, 23789, 23801, 23813, 23819, 23827, 23831,
    23833, 23857, 23869, 23873, 23879, 23887, 23893, 23899, 23909, 23911, 23917,
    23929, 23957, 23971, 23977, 23981, 23993, 24001, 24007, 24019, 24023, 24029,
    24043, 24049, 24061, 24071, 24077, 24083, 24091, 24097, 24103, 24107, 24109,
    24113, 24121, 24133, 24137, 24151, 24169, 24179, 24181, 24197, 24203, 24223,
    24229, 24239, 24247, 24251, 24281, 24317, 24329, 24337, 24359, 24371, 24373,
    24379, 24391, 24407, 24413, 24419, 24421, 24439, 24443, 24469, 24473, 24481,
    24499, 24509, 24517, 24527, 24533, 24547, 24551, 24571, 24593, 24611, 24623,
    24631, 24659, 24671, 24677, 24683, 24691, 24697, 24709, 24733, 24749, 24763,
    24767, 24781, 24793, 24799, 24809, 24821, 24841, 24847, 24851, 24859, 24877,
    24889, 24907, 24917, 24919, 24923, 24943, 24953, 24967, 24971, 24977, 24979,
    24989, 25013, 25031, 25033, 25037, 25057, 25073, 25087, 25097, 25111, 25117,
    25121, 25127, 25147, 25153, 25163, 25169, 25171, 25183, 25189, 25219, 25229,
    25237, 25243, 25247, 25253, 25261, 25301, 25303, 25307, 25309, 25321, 25339,
    25343, 25349, 25357, 25367, 25373, 25391, 25409, 25411, 25423, 25439, 25447,
    25453, 25457, 25463, 25469, 25471, 25523, 25537, 25541, 25561, 25577, 25579,
    25583, 25589, 25601, 25603, 25609, 25621, 25633, 25639, 25643, 25657, 25667,
    25673, 25679, 25693, 25703, 25717, 25733, 25741, 25747, 25759, 25763, 25771,
    25793, 25799, 25801, 25819, 25841, 25847, 25849, 25867, 25873, 25889, 25903,
    25913, 25919, 25931, 25933, 25939, 25943, 25951, 25969, 25981, 25997, 25999,
    26003, 26017, 26021, 26029, 26041, 26053, 26083, 26099, 26107, 26111, 26113,
    26119, 26141, 26153, 26161, 26171, 26177, 26183, 26189, 26203, 26209, 26227,
    26237, 26249, 26251, 26261, 26263, 26267, 26293, 26297, 26309, 26317, 26321,
    26339, 26347, 26357, 26371, 26387, 26393, 26399, 26407, 26417, 26423, 26431,
    26437, 26449, 26459, 26479, 26489, 26497, 26501, 26513, 26539, 26557, 26561,
    26573, 26591, 26597, 26627, 26633, 26641, 26647, 26669, 26681, 26683, 26687,
    26693, 26699, 26701, 26711, 26713, 26717, 26723, 26729, 26731, 26737, 26759,
    26777, 26783, 26801, 26813, 26821, 26833, 26839, 26849, 26861, 26863, 26879,
    26881, 26891, 26893, 26903, 26921, 26927, 26947, 26951, 26953, 26959, 26981,
    26987, 26993, 27011, 27017, 27031, 27043, 27059, 27061, 27067, 27073, 27077,
    27091, 27103, 27107, 27109, 27127, 27143, 27179, 27191, 27197, 27211, 27239,
    27241, 27253, 27259, 27271, 27277, 27281, 27283, 27299, 27329, 27337, 27361,
    27367, 27397, 27407, 27409, 27427, 27431, 27437, 27449, 27457, 27479, 27481,
    27487, 27509, 27527, 27529, 27539, 27541, 27551, 27581, 27583, 27611, 27617,
    27631, 27647, 27653, 27673, 27689, 27691, 27697, 27701, 27733, 27737, 27739,
    27743, 27749, 27751, 27763, 27767, 27773, 27779, 27791, 27793, 27799, 27803,
    27809, 27817, 27823, 27827, 27847, 27851, 27883, 27893, 27901, 27917, 27919,
    27941, 27943, 27947, 27953, 27961, 27967, 27983, 27997, 28001, 28019, 28027,
    28031, 28051, 28057, 28069, 28081, 28087, 28097, 28099, 28109, 28111, 28123,
    28151, 28163, 28181, 28183, 28201, 28211, 28219, 28229, 28277, 28279, 28283,
    28289, 28297, 28307, 28309, 28319, 28349, 28351, 28387, 28393, 28403, 28409,
    28411, 28429, 28433, 28439, 28447, 28463, 28477, 28493, 28499, 28513, 28517,
    28537, 28541, 28547, 28549, 28559, 28571, 28573, 28579, 28591, 28597, 28603,
    28607, 28619, 28621, 28627, 28631, 28643, 28649, 28657, 28661, 28663, 28669,
    28687, 28697, 28703, 28711, 28723, 28729, 28751, 28753, 28759, 28771, 28789,
    28793, 28807, 28813, 28817, 28837, 28843, 28859, 28867, 28871, 28879, 28901,
    28909, 28921, 28927, 28933, 28949, 28961, 28979, 29009, 29017, 29021, 29023,
    29027, 29033, 29059, 29063, 29077, 29101, 29123, 29129, 29131, 29137, 29147,
    29153, 29167, 29173, 29179, 29191, 29201, 29207, 29209, 29221, 29231, 29243,
    29251, 29269, 29287, 29297, 29303, 29311, 29327, 29333, 29339, 29347, 29363,
    29383, 29387, 29389, 29399, 29401, 29411, 29423, 29429, 29437, 29443, 29453,
    29473, 29483, 29501, 29527, 29531, 29537, 29567, 29569, 29573, 29581, 29587,
    29599, 29611, 29629, 29633, 29641, 29663, 29669, 29671, 29683, 29717, 29723,
    29741, 29753, 29759, 29761, 29789, 29803, 29819, 29833, 29837, 29851, 29863,
    29867, 29873, 29879, 29881, 29917, 29921, 29927, 29947, 29959, 29983, 29989,
    30011, 30013, 30029, 30047, 30059, 30071, 30089, 30091, 30097, 30103, 30109,
    30113, 30119, 30133, 30137, 30139, 30161, 30169, 30181, 30187, 30197, 30203,
    30211, 30223, 30241, 30253, 30259, 30269, 30271, 30293, 30307, 30313, 30319,
    30323, 30341, 30347, 30367, 30389, 30391, 30403, 30427, 30431, 30449, 30467,
    30469, 30491, 30493, 30497, 30509, 30517, 30529, 30539, 30553, 30557, 30559,
    30577, 30593, 30631, 30637, 30643, 30649, 30661, 30671, 30677, 30689, 30697,
    30703, 30707, 30713, 30727, 30757, 30763, 30773, 30781, 30803, 30809, 30817,
    30829, 30839, 30841, 30851, 30853, 30859, 30869, 30871, 30881, 30893, 30911,
    30931, 30937, 30941, 30949, 30971, 30977, 30983, 31013, 31019, 31033, 31039,
    31051, 31063, 31069, 31079, 31081, 31091, 31121, 31123, 31139, 31147, 31151,
    31153, 31159, 31177, 31181, 31183, 31189, 31193, 31219, 31223, 31231, 31237,
    31247, 31249, 31253, 31259, 31267, 31271, 31277, 31307, 31319, 31321, 31327,
    31333, 31337, 31357, 31379, 31387, 31391, 31393, 31397, 31469, 31477, 31481,
    31489, 31511, 31513, 31517, 31531, 31541, 31543, 31547, 31567, 31573, 31583,
    31601, 31607, 31627, 31643, 31649, 31657, 31663, 31667, 31687, 31699, 31721,
    31723, 31727, 31729, 31741, 31751, 31769, 31771, 31793, 31799, 31817, 31847,
    31849, 31859, 31873, 31883, 31891, 31907, 31957, 31963, 31973, 31981, 31991,
    32003, 32009, 32027, 32029, 32051, 32057, 32059, 32063, 32069, 32077, 32083,
    32089, 32099, 32117, 32119, 32141, 32143, 32159, 32173, 32183, 32189, 32191,
    32203, 32213, 32233, 32237, 32251, 32257, 32261, 32297, 32299, 32303, 32309,
    32321, 32323, 32327, 32341, 32353, 32359, 32363, 32369, 32371, 32377, 32381,
    32401, 32411, 32413, 32423, 32429, 32441, 32443, 32467, 32479, 32491, 32497,
    32503, 32507, 32531, 32533, 32537, 32561, 32563, 32569, 32573, 32579, 32587,
    32603, 32609, 32611, 32621, 32633, 32647, 32653, 32687, 32693, 32707, 32713,
    32717, 32719, 32749, 32771, 32779, 32783, 32789, 32797, 32801, 32803, 32831,
    32833, 32839, 32843, 32869, 32887, 32909, 32911, 32917, 32933, 32939, 32941,
    32957, 32969, 32971, 32983, 32987, 32993, 32999, 33013, 33023, 33029, 33037,
    33049, 33053, 33071, 33073, 33083, 33091, 33107, 33113, 33119, 33149, 33151,
    33161, 33179, 33181, 33191, 33199, 33203, 33211, 33223, 33247, 33287, 33289,
    33301, 33311, 33317, 33329, 33331, 33343, 33347, 33349, 33353, 33359, 33377,
    33391, 33403, 33409, 33413, 33427, 33457, 33461, 33469, 33479, 33487, 33493,
    33503, 33521, 33529, 33533, 33547, 33563, 33569, 33577, 33581, 33587, 33589,
    33599, 33601, 33613, 33617, 33619, 33623, 33629, 33637, 33641, 33647, 33679,
    33703, 33713, 33721, 33739, 33749, 33751, 33757, 33767, 33769, 33773, 33791,
    33797, 33809, 33811, 33827, 33829, 33851, 33857, 33863, 33871, 33889, 33893,
    33911, 33923, 33931, 33937, 33941, 33961, 33967, 33997, 34019, 34031, 34033,
    34039, 34057, 34061, 34123, 34127, 34129, 34141, 34147, 34157, 34159, 34171,
    34183, 34211, 34213, 34217, 34231, 34253, 34259, 34261, 34267, 34273, 34283,
    34297, 34301, 34303, 34313, 34319, 34327, 34337, 34351, 34361, 34367, 34369,
    34381, 34403, 34421, 34429, 34439, 34457, 34469, 34471, 34483, 34487, 34499,
    34501, 34511, 34513, 34519, 34537, 34543, 34549, 34583, 34589, 34591, 34603,
    34607, 34613, 34631, 34649, 34651, 34667, 34673, 34679, 34687, 34693, 34703,
    34721, 34729, 34739, 34747, 34757, 34759, 34763, 34781, 34807, 34819, 34841,
    34843, 34847, 34849, 34871, 34877, 34883, 34897, 34913, 34919, 34939, 34949,
    34961, 34963, 34981, 35023, 35027, 35051, 35053, 35059, 35069, 35081, 35083,
    35089, 35099, 35107, 35111, 35117, 35129, 35141, 35149, 35153, 35159, 35171,
    35201, 35221, 35227, 35251, 35257, 35267, 35279, 35281, 35291, 35311, 35317,
    35323, 35327, 35339, 35353, 35363, 35381, 35393, 35401, 35407, 35419, 35423,
    35437, 35447, 35449, 35461, 35491, 35507, 35509, 35521, 35527, 35531, 35533,
    35537, 35543, 35569, 35573, 35591, 35593, 35597, 35603, 35617, 35671, 35677,
    35729, 35731, 35747, 35753, 35759, 35771, 35797, 35801, 35803, 35809, 35831,
    35837, 35839, 35851, 35863, 35869, 35879, 35897, 35899, 35911, 35923, 35933,
    35951, 35963, 35969, 35977, 35983, 35993, 35999, 36007, 36011, 36013, 36017,
    36037, 36061, 36067, 36073, 36083, 36097, 36107, 36109, 36131, 36137, 36151,
    36161, 36187, 36191, 36209, 36217, 36229, 36241, 36251, 36263, 36269, 36277,
    36293, 36299, 36307, 36313, 36319, 36341, 36343, 36353, 36373, 36383, 36389,
    36433, 36451, 36457, 36467, 36469, 36473, 36479, 36493, 36497, 36523, 36527,
    36529, 36541, 36551, 36559, 36563, 36571, 36583, 36587, 36599, 36607, 36629,
    36637, 36643, 36653, 36671, 36677, 36683, 36691, 36697, 36709, 36713, 36721,
    36739, 36749, 36761, 36767, 36779, 36781, 36787, 36791, 36793, 36809, 36821,
    36833, 36847, 36857, 36871, 36877, 36887, 36899, 36901, 36913, 36919, 36923,
    36929, 36931, 36943, 36947, 36973, 36979, 36997, 37003, 37013, 37019, 37021,
    37039, 37049, 37057, 37061, 37087, 37097, 37117, 37123, 37139, 37159, 37171,
    37181, 37189, 37199, 37201, 37217, 37223, 37243, 37253, 37273, 37277, 37307,
    37309, 37313, 37321, 37337, 37339, 37357, 37361, 37363, 37369, 37379, 37397,
    37409, 37423, 37441, 37447, 37463, 37483, 37489, 37493, 37501, 37507, 37511,
    37517, 37529, 37537, 37547, 37549, 37561, 37567, 37571, 37573, 37579, 37589,
    37591, 37607, 37619, 37633, 37643, 37649, 37657, 37663, 37691, 37693, 37699,
    37717, 37747, 37781, 37783, 37799, 37811, 37813, 37831, 37847, 37853, 37861,
    37871, 37879, 37889, 37897, 37907, 37951, 37957, 37963, 37967, 37987, 37991,
    37993, 37997, 38011, 38039, 38047, 38053, 38069, 38083, 38113, 38119, 38149,
    38153, 38167, 38177, 38183, 38189, 38197, 38201, 38219, 38231, 38237, 38239,
    38261, 38273, 38281, 38287, 38299, 38303, 38317, 38321, 38327, 38329, 38333,
    38351, 38371, 38377, 38393, 38431, 38447, 38449, 38453, 38459, 38461, 38501,
    38543, 38557, 38561, 38567, 38569, 38593, 38603, 38609, 38611, 38629, 38639,
    38651, 38653, 38669, 38671, 38677, 38693, 38699, 38707, 38711, 38713, 38723,
    38729, 38737, 38747, 38749, 38767, 38783, 38791, 38803, 38821, 38833, 38839,
    38851, 38861, 38867, 38873,
};

static bool TestPrimeChecking(BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> p(BN_new());
  int is_probably_prime_1 = 0, is_probably_prime_2 = 0;

  const int max_prime = kPrimes[OPENSSL_ARRAY_SIZE(kPrimes)-1];
  size_t next_prime_index = 0;

  for (int i = 0; i <= max_prime; i++) {
    bool is_prime = false;

    if (i == kPrimes[next_prime_index]) {
      is_prime = true;
      next_prime_index++;
    }

    if (!BN_set_word(p.get(), i) ||
        !BN_primality_test(&is_probably_prime_1, p.get(), BN_prime_checks, ctx,
                           false /* do_trial_division */,
                           nullptr /* callback */) ||
        is_probably_prime_1 != (is_prime ? 1 : 0) ||
        !BN_primality_test(&is_probably_prime_2, p.get(), BN_prime_checks, ctx,
                           true /* do_trial_division */,
                           nullptr /* callback */) ||
        is_probably_prime_2 != (is_prime ? 1 : 0)) {
      fprintf(stderr,
              "TestPrimeChecking failed for %d (is_prime: %d vs %d without "
              "trial division vs %d with it)\n",
              i, static_cast<int>(is_prime), is_probably_prime_1,
              is_probably_prime_2);
      return false;
    }
  }

  // Negative numbers are not prime.
  if (!BN_set_word(p.get(), 7)) {
    return false;
  }
  BN_set_negative(p.get(), 1);
  if (!BN_primality_test(&is_probably_prime_1, p.get(), BN_prime_checks, ctx,
                         false /* do_trial_division */,
                         nullptr /* callback */) ||
      is_probably_prime_1 != 0 ||
      !BN_primality_test(&is_probably_prime_2, p.get(), BN_prime_checks, ctx,
                         true /* do_trial_division */,
                         nullptr /* callback */) ||
      is_probably_prime_2 != 0) {
    fprintf(stderr,
            "TestPrimeChecking failed for -7 (is_prime: 0 vs %d without "
            "trial division vs %d with it)\n",
            is_probably_prime_1, is_probably_prime_2);
    return false;
  }

  return true;
}

int main(int argc, char *argv[]) {
  CRYPTO_library_init();

  if (argc != 2) {
    fprintf(stderr, "%s TEST_FILE\n", argv[0]);
    return 1;
  }

  bssl::UniquePtr<BN_CTX> ctx(BN_CTX_new());
  if (!ctx) {
    return 1;
  }

  if (!TestBN2BinPadded(ctx.get()) ||
      !TestDec2BN(ctx.get()) ||
      !TestHex2BN(ctx.get()) ||
      !TestASC2BN(ctx.get()) ||
      !TestLittleEndian() ||
      !TestMPI() ||
      !TestRand() ||
      !TestRandRange() ||
      !TestASN1() ||
      !TestNegativeZero(ctx.get()) ||
      !TestBadModulus(ctx.get()) ||
      !TestExpModZero() ||
      !TestSmallPrime(ctx.get()) ||
      !TestCmpWord() ||
      !TestBN2Dec() ||
      !TestBNSetGetU64() ||
      !TestBNPow2(ctx.get()) ||
      !TestPrimeChecking(ctx.get())) {
    ERR_print_errors_fp(stderr);
    return 1;
  }

  return FileTestMain(RunTest, ctx.get(), argv[1]);
}
