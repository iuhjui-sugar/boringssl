/* Originally written by Bodo Moeller for the OpenSSL project.
 * ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The elliptic curve binary polynomial software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems
 * Laboratories. */

#include <openssl/ec.h>

#include <assert.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>

#include "internal.h"
#include "../internal.h"


const struct built_in_curve OPENSSL_built_in_curves[] = {
    {
        NID_secp224r1,
        "NIST P-224",
        &EC_p224,
        /* 1.3.132.0.33 */
        {0x2b, 0x81, 0x04, 0x00, 0x21},
        5,
    },
    {
        NID_X9_62_prime256v1,
        "NIST P-256",
        &EC_p256,
        /* 1.2.840.10045.3.1.7 */
        {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
        8,
    },
    {
        NID_secp384r1,
        "NIST P-384",
        &EC_p384,
        /* 1.3.132.0.34 */
        {0x2b, 0x81, 0x04, 0x00, 0x22},
        5,
    },
    {
        NID_secp521r1,
        "NIST P-521",
        &EC_p521,
        /* 1.3.132.0.35 */
        {0x2b, 0x81, 0x04, 0x00, 0x23},
        5,
    },
    {NID_undef, NULL, NULL, {0}, 0},
};


EC_GROUP *ec_group_new(const EC_METHOD *meth) {
  EC_GROUP *ret;

  if (meth == NULL) {
    OPENSSL_PUT_ERROR(EC, EC_R_SLOT_FULL);
    return NULL;
  }

  if (meth->group_init == 0) {
    OPENSSL_PUT_ERROR(EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return NULL;
  }

  ret = OPENSSL_malloc(sizeof(EC_GROUP));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(EC, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  memset(ret, 0, sizeof(EC_GROUP));

  ret->meth = meth;
  BN_init(&ret->order);

  if (!meth->group_init(ret)) {
    OPENSSL_free(ret);
    return NULL;
  }

  return ret;
}

EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a,
                                 const BIGNUM *b, BN_CTX *ctx) {
  EC_GROUP *ret = ec_group_new(&EC_GFp_mont_method);
  if (ret == NULL) {
    return NULL;
  }

  if (ret->meth->group_set_curve == 0) {
    OPENSSL_PUT_ERROR(EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return 0;
  }
  if (!ret->meth->group_set_curve(ret, p, a, b, ctx)) {
    EC_GROUP_free(ret);
    return NULL;
  }
  return ret;
}

int EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator,
                           const BIGNUM *order, const BIGNUM *cofactor) {
  if (group->curve_name != NID_undef || group->generator != NULL ||
      group->order_mont != NULL) {
    /* |EC_GROUP_set_generator| may only be used with |EC_GROUP|s returned by
     * |EC_GROUP_new_curve_GFp| and may only used once on each group. */
    return 0;
  }

  /* Require a cofactor of one for custom curves, which implies prime order. */
  if (!BN_is_one(cofactor)) {
    OPENSSL_PUT_ERROR(EC, EC_R_INVALID_COFACTOR);
    return 0;
  }

  BN_CTX *ctx = BN_CTX_new();
  if (ctx == NULL) {
    return 0;
  }

  group->order_mont = BN_MONT_CTX_new();
  int mont_ok = group->order_mont != NULL &&
                BN_MONT_CTX_set(group->order_mont, order, ctx);
  BN_CTX_free(ctx);
  if (!mont_ok) {
    BN_MONT_CTX_free(group->order_mont);
    group->order_mont = NULL;
    return 0;
  }

  group->generator = EC_POINT_new(group);
  return group->generator != NULL &&
         EC_POINT_copy(group->generator, generator) &&
         BN_copy(&group->order, order);
}

EC_GROUP *EC_GROUP_new_by_curve_name(int nid) {
  for (unsigned i = 0; OPENSSL_built_in_curves[i].nid != NID_undef; i++) {
    const struct built_in_curve *curve = &OPENSSL_built_in_curves[i];
    if (curve->nid == nid) {
      /* This returns a non-const pointer for historical reasons. */
      return (EC_GROUP *)curve->group();
    }
  }

  OPENSSL_PUT_ERROR(EC, EC_R_UNKNOWN_GROUP);
  return NULL;
}

void EC_GROUP_free(EC_GROUP *group) {
  /* For historical reasons, built-in groups are usable with |EC_GROUP_free|,
   * but it is a no-op. */
  if (!group || group->curve_name != NID_undef) {
    return;
  }

  if (group->meth->group_finish != 0) {
    group->meth->group_finish(group);
  }

  BN_MONT_CTX_free(group->order_mont);
  EC_POINT_free(group->generator);
  BN_free(&group->order);

  OPENSSL_free(group);
}

static BN_MONT_CTX *bn_mont_ctx_dup(const BN_MONT_CTX *mont) {
  BN_MONT_CTX *ret = BN_MONT_CTX_new();
  if (ret == NULL ||
      !BN_MONT_CTX_copy(ret, mont)) {
    BN_MONT_CTX_free(ret);
    return NULL;
  }

  return ret;
}

EC_GROUP *EC_GROUP_dup(const EC_GROUP *a) {
  /* For historical reasons, built-in groups are usable with |EC_GROUP_dup|, but
   * it is a no-op. */
  if (a == NULL || a->curve_name != NID_undef) {
    return (EC_GROUP *)a;
  }

  if (a->meth->group_copy == NULL) {
    OPENSSL_PUT_ERROR(EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return NULL;
  }

  EC_GROUP *ret = ec_group_new(a->meth);
  if (ret == NULL) {
    return NULL;
  }

  if (a->order_mont != NULL) {
    ret->order_mont = bn_mont_ctx_dup(a->order_mont);
    if (ret->order_mont == NULL) {
      goto err;
    }
  }

  if (a->generator != NULL) {
    ret->generator = EC_POINT_dup(a->generator, ret);
    if (ret->generator == NULL) {
      goto err;
    }
  }

  if (!BN_copy(&ret->order, &a->order) ||
      !ret->meth->group_copy(ret, a)) {
    goto err;
  }

  return ret;

err:
  EC_GROUP_free(ret);
  return NULL;
}

int EC_GROUP_cmp(const EC_GROUP *a, const EC_GROUP *b, BN_CTX *ignored) {
  return a->curve_name == NID_undef ||
         b->curve_name == NID_undef ||
         a->curve_name != b->curve_name;
}

const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *group) {
  return group->generator;
}

const BIGNUM *EC_GROUP_get0_order(const EC_GROUP *group) {
  assert(!BN_is_zero(&group->order));
  return &group->order;
}

int EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx) {
  if (BN_copy(order, EC_GROUP_get0_order(group)) == NULL) {
    return 0;
  }
  return 1;
}

int EC_GROUP_get_cofactor(const EC_GROUP *group, BIGNUM *cofactor,
                          BN_CTX *ctx) {
  /* All |EC_GROUP|s have cofactor 1. */
  return BN_set_word(cofactor, 1);
}

int EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *out_p, BIGNUM *out_a,
                           BIGNUM *out_b, BN_CTX *ctx) {
  return ec_GFp_simple_group_get_curve(group, out_p, out_a, out_b, ctx);
}

int EC_GROUP_get_curve_name(const EC_GROUP *group) { return group->curve_name; }

unsigned EC_GROUP_get_degree(const EC_GROUP *group) {
  return ec_GFp_simple_group_get_degree(group);
}

EC_POINT *EC_POINT_new(const EC_GROUP *group) {
  EC_POINT *ret;

  if (group == NULL) {
    OPENSSL_PUT_ERROR(EC, ERR_R_PASSED_NULL_PARAMETER);
    return NULL;
  }

  ret = OPENSSL_malloc(sizeof *ret);
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(EC, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  ret->meth = group->meth;

  if (!ec_GFp_simple_point_init(ret)) {
    OPENSSL_free(ret);
    return NULL;
  }

  return ret;
}

void EC_POINT_free(EC_POINT *point) {
  if (!point) {
    return;
  }

  ec_GFp_simple_point_finish(point);

  OPENSSL_free(point);
}

void EC_POINT_clear_free(EC_POINT *point) {
  if (!point) {
    return;
  }

  ec_GFp_simple_point_clear_finish(point);

  OPENSSL_cleanse(point, sizeof *point);
  OPENSSL_free(point);
}

int EC_POINT_copy(EC_POINT *dest, const EC_POINT *src) {
  if (dest->meth != src->meth) {
    OPENSSL_PUT_ERROR(EC, EC_R_INCOMPATIBLE_OBJECTS);
    return 0;
  }
  if (dest == src) {
    return 1;
  }
  return ec_GFp_simple_point_copy(dest, src);
}

EC_POINT *EC_POINT_dup(const EC_POINT *a, const EC_GROUP *group) {
  if (a == NULL) {
    return NULL;
  }

  EC_POINT *ret = EC_POINT_new(group);
  if (ret == NULL ||
      !EC_POINT_copy(ret, a)) {
    EC_POINT_free(ret);
    return NULL;
  }

  return ret;
}

int EC_POINT_set_to_infinity(const EC_GROUP *group, EC_POINT *point) {
  if (group->meth != point->meth) {
    OPENSSL_PUT_ERROR(EC, EC_R_INCOMPATIBLE_OBJECTS);
    return 0;
  }
  return ec_GFp_simple_point_set_to_infinity(group, point);
}

int EC_POINT_is_at_infinity(const EC_GROUP *group, const EC_POINT *point) {
  if (group->meth != point->meth) {
    OPENSSL_PUT_ERROR(EC, EC_R_INCOMPATIBLE_OBJECTS);
    return 0;
  }
  return ec_GFp_simple_is_at_infinity(group, point);
}

int EC_POINT_is_on_curve(const EC_GROUP *group, const EC_POINT *point,
                         BN_CTX *ctx) {
  if (group->meth != point->meth) {
    OPENSSL_PUT_ERROR(EC, EC_R_INCOMPATIBLE_OBJECTS);
    return 0;
  }
  return ec_GFp_simple_is_on_curve(group, point, ctx);
}

int EC_POINT_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b,
                 BN_CTX *ctx) {
  if ((group->meth != a->meth) || (a->meth != b->meth)) {
    OPENSSL_PUT_ERROR(EC, EC_R_INCOMPATIBLE_OBJECTS);
    return -1;
  }
  return ec_GFp_simple_cmp(group, a, b, ctx);
}

int EC_POINT_make_affine(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx) {
  if (group->meth != point->meth) {
    OPENSSL_PUT_ERROR(EC, EC_R_INCOMPATIBLE_OBJECTS);
    return 0;
  }
  return ec_GFp_simple_make_affine(group, point, ctx);
}

int EC_POINTs_make_affine(const EC_GROUP *group, size_t num, EC_POINT *points[],
                          BN_CTX *ctx) {
  size_t i;

  for (i = 0; i < num; i++) {
    if (group->meth != points[i]->meth) {
      OPENSSL_PUT_ERROR(EC, EC_R_INCOMPATIBLE_OBJECTS);
      return 0;
    }
  }
  return ec_GFp_simple_points_make_affine(group, num, points, ctx);
}

int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group,
                                        const EC_POINT *point, BIGNUM *x,
                                        BIGNUM *y, BN_CTX *ctx) {
  if (group->meth->point_get_affine_coordinates == 0) {
    OPENSSL_PUT_ERROR(EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return 0;
  }
  if (group->meth != point->meth) {
    OPENSSL_PUT_ERROR(EC, EC_R_INCOMPATIBLE_OBJECTS);
    return 0;
  }
  return group->meth->point_get_affine_coordinates(group, point, x, y, ctx);
}

int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *point,
                                        const BIGNUM *x, const BIGNUM *y,
                                        BN_CTX *ctx) {
  if (group->meth != point->meth) {
    OPENSSL_PUT_ERROR(EC, EC_R_INCOMPATIBLE_OBJECTS);
    return 0;
  }
  if (!ec_GFp_simple_point_set_affine_coordinates(group, point, x, y, ctx)) {
    return 0;
  }

  if (!EC_POINT_is_on_curve(group, point, ctx)) {
    OPENSSL_PUT_ERROR(EC, EC_R_POINT_IS_NOT_ON_CURVE);
    return 0;
  }

  return 1;
}

int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                 const EC_POINT *b, BN_CTX *ctx) {
  if ((group->meth != r->meth) || (r->meth != a->meth) ||
      (a->meth != b->meth)) {
    OPENSSL_PUT_ERROR(EC, EC_R_INCOMPATIBLE_OBJECTS);
    return 0;
  }
  return ec_GFp_simple_add(group, r, a, b, ctx);
}


int EC_POINT_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                 BN_CTX *ctx) {
  if ((group->meth != r->meth) || (r->meth != a->meth)) {
    OPENSSL_PUT_ERROR(EC, EC_R_INCOMPATIBLE_OBJECTS);
    return 0;
  }
  return ec_GFp_simple_dbl(group, r, a, ctx);
}


int EC_POINT_invert(const EC_GROUP *group, EC_POINT *a, BN_CTX *ctx) {
  if (group->meth != a->meth) {
    OPENSSL_PUT_ERROR(EC, EC_R_INCOMPATIBLE_OBJECTS);
    return 0;
  }
  return ec_GFp_simple_invert(group, a, ctx);
}

int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *g_scalar,
                 const EC_POINT *p, const BIGNUM *p_scalar, BN_CTX *ctx) {
  /* Previously, this function set |r| to the point at infinity if there was
   * nothing to multiply. But, nobody should be calling this function with
   * nothing to multiply in the first place. */
  if ((g_scalar == NULL && p_scalar == NULL) ||
      ((p == NULL) != (p_scalar == NULL)))  {
    OPENSSL_PUT_ERROR(EC, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  if (group->meth != r->meth ||
      (p != NULL && group->meth != p->meth)) {
    OPENSSL_PUT_ERROR(EC, EC_R_INCOMPATIBLE_OBJECTS);
    return 0;
  }

  return group->meth->mul(group, r, g_scalar, p, p_scalar, ctx);
}

int ec_point_set_Jprojective_coordinates_GFp(const EC_GROUP *group, EC_POINT *point,
                                             const BIGNUM *x, const BIGNUM *y,
                                             const BIGNUM *z, BN_CTX *ctx) {
  if (group->meth != point->meth) {
    OPENSSL_PUT_ERROR(EC, EC_R_INCOMPATIBLE_OBJECTS);
    return 0;
  }
  return ec_GFp_simple_set_Jprojective_coordinates_GFp(group, point, x, y, z,
                                                       ctx);
}

void EC_GROUP_set_asn1_flag(EC_GROUP *group, int flag) {}

const EC_METHOD *EC_GROUP_method_of(const EC_GROUP *group) {
  return NULL;
}

int EC_METHOD_get_field_type(const EC_METHOD *meth) {
  return NID_X9_62_prime_field;
}

void EC_GROUP_set_point_conversion_form(EC_GROUP *group,
                                        point_conversion_form_t form) {
  if (form != POINT_CONVERSION_UNCOMPRESSED) {
    abort();
  }
}

size_t EC_get_builtin_curves(EC_builtin_curve *out_curves,
                             size_t max_num_curves) {
  unsigned num_built_in_curves;
  for (num_built_in_curves = 0;; num_built_in_curves++) {
    if (OPENSSL_built_in_curves[num_built_in_curves].nid == NID_undef) {
      break;
    }
  }

  for (unsigned i = 0; i < max_num_curves && i < num_built_in_curves; i++) {
    out_curves[i].comment = OPENSSL_built_in_curves[i].comment;
    out_curves[i].nid = OPENSSL_built_in_curves[i].nid;
  }

  return num_built_in_curves;
}
