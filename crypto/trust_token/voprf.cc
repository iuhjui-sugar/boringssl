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

#include <openssl/trust_token.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/nid.h>

#include "internal.h"
#include "../fipsmodule/ec/internal.h"

static EC_POINT *h_gen() {
  EC_GROUP *group(EC_GROUP_new_by_curve_name(NID_secp521r1));
  if (group == NULL) {
    return NULL;
  }

  BIGNUM *gx = BN_new();
  BIGNUM *gy = BN_new();
  BN_hex2bn(&gx,
            "210274a4652ac3fff4eeb040d1eae13bdad8a1b1f8ba87895815a5f721c18ff319"
            "f958439f0ddf9b2e6a9dbd8c3bf66d21e08a7634ab5be213e812bd32fd166632");
  BN_hex2bn(&gy,
            "97afe06530533bda23dd84b941402ae817a3d1a79a909e2cf6fd75758b11a7f08b"
            "1668c3b7492558d153b9c8e0b9bf3900e3194b81797aa2ca0761560bcb7e5b46");
  EC_POINT *pt = EC_POINT_new(group);
  EC_POINT_set_affine_coordinates_GFp(group, pt, gx, gy, NULL);
  return pt;
}

static int keypair(BIGNUM **out_x, BIGNUM **out_y, EC_POINT **out_pub,
                   EC_GROUP *group) {
  EC_POINT *H = h_gen();

  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();

  EC_POINT *pub = EC_POINT_new(group);
  if (pub == NULL ||
      !BN_rand_range_ex(x, 1, &group->order) ||
      !BN_rand_range_ex(y, 1, &group->order) ||
      !EC_POINT_mul(group, pub, x, H, y, NULL)) {
    BN_free(x);
    BN_free(y);
    EC_POINT_free(pub);
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  *out_x = x;
  *out_y = y;
  *out_pub = pub;

  return 1;
}

int VOPRF_Setup(BIGNUM **out_x0, BIGNUM **out_y0, EC_POINT **out_pub0,
                BIGNUM **out_x1, BIGNUM **out_y1, EC_POINT **out_pub1,
                BIGNUM **out_xs, BIGNUM **out_ys, EC_POINT **out_pubs,
                EC_GROUP **out_group) {
  EC_GROUP *group(EC_GROUP_new_by_curve_name(NID_secp521r1));
  if (group == NULL) {
    return 0;
  }

  BIGNUM *x0 = NULL, *x1 = NULL, *xs = NULL, *y0 = NULL, *y1 = NULL, *ys = NULL;
  EC_POINT *pub0 = NULL, *pub1 = NULL, *pubs = NULL;
  if (!keypair(&x0, &y0, &pub0, group) ||
      !keypair(&x1, &y1, &pub1, group) ||
      !keypair(&xs, &ys, &pubs, group)) {
    BN_free(x0);
    BN_free(y0);
    BN_free(x1);
    BN_free(y1);
    BN_free(xs);
    BN_free(ys);
    EC_POINT_free(pub0);
    EC_POINT_free(pub1);
    EC_POINT_free(pubs);
    return 0;
  }

  *out_x0 = x0;
  *out_y0 = y0;
  *out_pub0 = pub0;
  *out_x1 = x1;
  *out_y1 = y1;
  *out_pub1 = pub1;
  *out_xs = xs;
  *out_ys = ys;
  *out_pubs = pubs;
  *out_group = group;
  return 1;
}
