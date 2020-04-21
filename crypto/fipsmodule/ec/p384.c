// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#if !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86_64) && \
    !defined(OPENSSL_SMALL)

#include <openssl/ec.h>
#include "p256_p384_common-x86_64.h"
#include "p384-x86_64.h"

typedef P384_POINT_AFFINE PRECOMP384_ROW[64];

#include "p384-x86_64-table.h"

// One converted into the Montgomery domain
static const BN_ULONG ONE_384[P384_LIMBS] = {
     TOBN(0xffffffff, 0x00000001) , TOBN(0x00000000, 0xffffffff),
     TOBN(0x00000000, 0x00000001) , TOBN(0x00000000, 0x00000000),
     TOBN(0x00000000, 0x00000000) , TOBN(0x00000000, 0x00000000)
};

// ecp_nistp384_select_w7 sets |*val| to |in_t[index-1]| if 1 <= |index| <= 64
// and all zeros (the point at infinity) if |index| is 0. This is done in
// constant time.
static inline void ecp_nistp384_select_w7_wrap(EC_RAW_POINT *val,
                                               const P384_POINT_AFFINE in_t[64], int index)
{
    P384_POINT_AFFINE tmp_affine;
    ecp_nistp384_select_w7(&tmp_affine, in_t, index);

    // Convert P384_POINT_AFFINE to EC_FELEM
    // The function ecp_nistp384_select_w7 assumes that the size of X/Y is 384 bits.
    // However, an EC_FELEM object uses an EC_MAX_BYTES arrays for x/y.
    OPENSSL_memcpy(val->X.bytes, tmp_affine.X, sizeof(tmp_affine.X));
    OPENSSL_memcpy(val->Y.bytes, tmp_affine.Y, sizeof(tmp_affine.Y));

    // Convert |val| from affine to Jacobian coordinates. We set Z to zero if |val|
    // is infinity and |ONE_384| otherwise. |val| was computed from the table,
    // so it is infinity iff |wvalue >> 1| is zero.
    OPENSSL_memset(val->Z.words, 0, sizeof(val->Z.words));
    copy_conditional(val->Z.words, ONE_384, is_not_zero(index), P384_LIMBS);
}

static void ecp_nistp384_point_mul_base(const EC_GROUP *group, EC_RAW_POINT *r,
                                        const EC_SCALAR *scalar)
{
  assert(group->field.width == P384_LIMBS);

  alignas(32) EC_RAW_POINT t;
  EC_FELEM    tmp;
  unsigned    index = 0;
  uint8_t     p_str[49] = {0};

  // Store scalar->bytes in a byte extended temporary location p_str
  OPENSSL_memcpy(p_str, scalar->bytes, 48);

  // First window
  unsigned wvalue = calc_first_wvalue(&index, p_str);

  ecp_nistp384_select_w7_wrap(r, ecp_nistp384_precomputed[0], wvalue >> 1);
  ec_felem_neg(group, &tmp, &r->Y);
  copy_conditional(r->Y.words, tmp.words, wvalue & 1, P384_LIMBS);

  for (int i = 1; i < 55; i++) {
    wvalue = calc_wvalue(&index, p_str);

    ecp_nistp384_select_w7_wrap(&t, ecp_nistp384_precomputed[i], wvalue >> 1);

    ec_felem_neg(group, &tmp, &t.Y);
    copy_conditional(t.Y.words, tmp.words, wvalue & 1, P384_LIMBS);

    ec_GFp_mont_add(group, r, r, &t);
  }
}

DEFINE_METHOD_FUNCTION(EC_METHOD, EC_GFp_nistp384_method) {
  out->group_init = ec_GFp_mont_group_init;
  out->group_finish = ec_GFp_mont_group_finish;
  out->group_set_curve = ec_GFp_mont_group_set_curve;
  out->point_get_affine_coordinates = ec_GFp_mont_point_get_affine_coordinates;
  out->add = ec_GFp_mont_add;
  out->dbl = ec_GFp_mont_dbl;
  out->mul = ec_GFp_mont_mul;
  out->mul_base = ecp_nistp384_point_mul_base;
  out->mul_public = ec_GFp_mont_mul_public;
  out->felem_mul = ec_GFp_mont_felem_mul;
  out->felem_sqr = ec_GFp_mont_felem_sqr;
  out->felem_to_bytes = ec_GFp_mont_felem_to_bytes;
  out->felem_from_bytes = ec_GFp_mont_felem_from_bytes;
  out->felem_reduce = ec_GFp_mont_felem_reduce;
  out->felem_exp = ec_GFp_mont_felem_exp;
  out->scalar_inv0_montgomery = ec_simple_scalar_inv0_montgomery;
  out->scalar_to_montgomery_inv_vartime =
      ec_simple_scalar_to_montgomery_inv_vartime;
  out->cmp_x_coordinate = ec_GFp_mont_cmp_x_coordinate;
}

#endif // !OPENSSL_NO_ASM && OPENSSL_X86_64 && !OPENSSL_SMALL
