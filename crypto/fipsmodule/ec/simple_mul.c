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

#include <openssl/ec.h>

#include <assert.h>

#include "internal.h"
#include "../bn/internal.h"
#include "../../internal.h"


static void ec_GFp_simple_mul_single(const EC_GROUP *group, EC_RAW_POINT *r,
                                     const EC_RAW_POINT *p,
                                     const EC_SCALAR *scalar) {
  // Compute a table of the first 16 multiples of |p| (and infinity) for
  // |ec_GFp_nistp_recode_scalar_bits|.
  EC_RAW_POINT precomp[17];
  ec_GFp_simple_point_set_to_infinity(group, &precomp[0]);
  ec_GFp_simple_point_copy(&precomp[1], p);
  for (size_t j = 2; j < OPENSSL_ARRAY_SIZE(precomp); j++) {
    if (j & 1) {
      ec_GFp_simple_add(group, &precomp[j], &precomp[1], &precomp[j - 1]);
    } else {
      ec_GFp_simple_dbl(group, &precomp[j], &precomp[j / 2]);
    }
  }

  // Divide bits in |scalar| into windows.
  unsigned bits = BN_num_bits(&group->order);
  int r_is_at_infinity = 1;
  for (unsigned i = bits; i <= bits; i--) {
    if (!r_is_at_infinity) {
      ec_GFp_simple_dbl(group, r, r);
    }
    if (i % 5 == 0) {
      // Compute the next window.
      const size_t width = group->order.width;
      uint8_t window = bn_is_bit_set_words(scalar->words, width, i + 4) << 5;
      window |= bn_is_bit_set_words(scalar->words, width, i + 3) << 4;
      window |= bn_is_bit_set_words(scalar->words, width, i + 2) << 3;
      window |= bn_is_bit_set_words(scalar->words, width, i + 1) << 2;
      window |= bn_is_bit_set_words(scalar->words, width, i) << 1;
      if (i > 0) {
        window |= bn_is_bit_set_words(scalar->words, width, i - 1);
      }
      uint8_t sign, digit;
      ec_GFp_nistp_recode_scalar_bits(&sign, &digit, window);

      // Select the entry in constant-time.
      EC_RAW_POINT tmp;
      for (size_t j = 0; j < OPENSSL_ARRAY_SIZE(precomp); j++) {
        BN_ULONG mask = constant_time_eq_w(j, digit);
        ec_felem_select(group, &tmp.X, mask, &precomp[j].X, &tmp.X);
        ec_felem_select(group, &tmp.Y, mask, &precomp[j].Y, &tmp.Y);
        ec_felem_select(group, &tmp.Z, mask, &precomp[j].Z, &tmp.Z);
      }

      // Negate if necessary.
      EC_FELEM neg_Y;
      ec_felem_neg(group, &neg_Y, &tmp.Y);
      BN_ULONG sign_mask = sign;
      sign_mask = 0u - sign_mask;
      ec_felem_select(group, &tmp.Y, sign_mask, &neg_Y, &tmp.Y);

      if (r_is_at_infinity) {
        ec_GFp_simple_point_copy(r, &tmp);
        r_is_at_infinity = 0;
      } else {
        ec_GFp_simple_add(group, r, r, &tmp);
      }
    }
  }
  if (r_is_at_infinity) {
    ec_GFp_simple_point_set_to_infinity(group, r);
  }
}

void ec_GFp_simple_mul(const EC_GROUP *group, EC_RAW_POINT *r,
                       const EC_SCALAR *g_scalar, const EC_RAW_POINT *p,
                       const EC_SCALAR *p_scalar) {
  assert(g_scalar != NULL || p_scalar != NULL);
  if (p_scalar == NULL) {
    ec_GFp_simple_mul_single(group, r, &group->generator->raw, g_scalar);
  } else if (g_scalar == NULL) {
    ec_GFp_simple_mul_single(group, r, p, p_scalar);
  } else {
    // Support constant-time two-point multiplication for compatibility.  This
    // does not actually come up in keygen, ECDH, or ECDSA, so we implement it
    // the naive way.
    ec_GFp_simple_mul_single(group, r, &group->generator->raw, g_scalar);
    EC_RAW_POINT tmp;
    ec_GFp_simple_mul_single(group, &tmp, p, p_scalar);
    ec_GFp_simple_add(group, r, r, &tmp);
  }
}
