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

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/trust_token.h>

#include "../fipsmodule/bn/internal.h"
#include "../fipsmodule/ec/internal.h"


// h_gen returns a randomly selected point for the Privacy Pass protocol.
//
// x:
// y:
//
// This point was generated with the following Python code.

/*
import hashlib
import numpy
import random

from fastecdsa.curve import P521
from fastecdsa.point import Point

SEED_N = 'VOPRF Point'

A = -3
B = 0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
P = 2**521 - 1

def expmod(b,e,m):
  if e == 0: return 1
  t = expmod(b,e/2,m)**2 % m
  if e & 1: t = (t*b) % m
  return t

def getX(y):
  value = y**3+A*y+B
  realX = expmod(value, (P+1)/4, P)
  return realX

def bit(h,i):
  return (ord(h[i/8]) >> (i%8)) & 1

b = 521
def decodepoint(so):
  s = hashlib.sha256(so + '0').digest() + hashlib.sha256(so + '1').digest() + hashlib.sha256(so + '2').digest()
  x = 0
  for i in range(0,b-1):
    x = x + (long(bit(s,i))<<i)
  y = getY(x)
  if x & 1 != bit(s,b-1): y = P-y
  P = [x,y]
  try:
    P2 = Point(x, y, curve=P521)
  except:
    raise Exception("decoding point that is not on curve")
  return P


def genpoint(seed):
    v = hashlib.sha256(seed).digest()
    it = 1
    while True:
        try:
            x,y = decodepoint(v)
        except:
            it += 1
            v = hashlib.sha256(v).digest()
            continue
        print("Found in %d iterations:" % it)
        print("  x = %d" % x)
        print("  y = %d" % y)
        print(" Encoded (hex)")
        print(hex(x), hex(y))
        return (x,y)

if __name__ == "__main__":
    N = genpoint(SEED_N)
*/

static EC_POINT *h_gen(void) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return NULL;
  }

  static const BN_ULONG kHGenX[] = {
      TOBN(0xe812bd32, 0xfd166632), TOBN(0xe08a7634, 0xab5be213),
      TOBN(0x6a9dbd8c, 0x3bf66d21), TOBN(0xf958439f, 0x0ddf9b2e),
      TOBN(0x15a5f721, 0xc18ff319), TOBN(0xd8a1b1f8, 0xba878958),
      TOBN(0xeeb040d1, 0xeae13bda), TOBN(0x0274a465, 0x2ac3fff4),
      TOBN(0x00000000, 0x00000021),
  };
  static const BIGNUM kX = STATIC_BIGNUM(kHGenX);

  static const BN_ULONG kHGenY[] = {
      TOBN(0x0761560b, 0xcb7e5b46), TOBN(0xe3194b81, 0x797aa2ca),
      TOBN(0x53b9c8e0, 0xb9bf3900), TOBN(0x1668c3b7, 0x492558d1),
      TOBN(0xfd75758b, 0x11a7f08b), TOBN(0xa3d1a79a, 0x909e2cf6),
      TOBN(0xdd84b941, 0x402ae817), TOBN(0xafe06530, 0x533bda23),
      TOBN(0x00000000, 0x00000097),
  };
  static const BIGNUM kY = STATIC_BIGNUM(kHGenY);

  EC_POINT *pt = EC_POINT_new(group);
  if (pt == NULL ||
      !EC_POINT_set_affine_coordinates_GFp(group, pt, &kX, &kY, NULL)) {
    return NULL;
  }
  return pt;
}

// generate_keypair generates a keypair for the Private Metadata construction in
// https://eprint.iacr.org/2020/072.pdf. |out_x| and |out_y| are set to the
// secret half of the keypair, while |*out_pub| is set to the public half of the
// keypair. It returns one on success and zero on failure.
static int generate_keypair(EC_SCALAR *out_x, EC_SCALAR *out_y,
                            EC_POINT **out_pub, const EC_GROUP *group) {
  EC_POINT *H = h_gen();
  if (H == NULL) {
    return 0;
  }

  static const uint8_t kDefaultAdditionalData[32] = {0};
  EC_RAW_POINT tmp1, tmp2;
  EC_POINT *pub = EC_POINT_new(group);
  if (pub == NULL ||
      !ec_random_nonzero_scalar(group, out_x, kDefaultAdditionalData) ||
      !ec_random_nonzero_scalar(group, out_y, kDefaultAdditionalData) ||
      !ec_point_mul_scalar_base(group, &tmp1, out_x) ||
      !ec_point_mul_scalar(group, &tmp2, &H->raw, out_y)) {
    EC_POINT_free(pub);
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  group->meth->add(group, &pub->raw, &tmp1, &tmp2);
  *out_pub = pub;

  return 1;
}

int TRUST_TOKEN_generate_key(uint8_t *out_priv_key, size_t *out_priv_key_len,
                             size_t max_priv_key_len, uint8_t *out_pub_key,
                             size_t *out_pub_key_len, size_t max_pub_key_len,
                             uint32_t id) {
  int ok = 0;
  EC_SCALAR x0, y0, x1, y1, xs, ys;
  EC_POINT *pub0 = NULL, *pub1 = NULL, *pubs = NULL;
  CBB cbb;
  uint8_t *buf = NULL;
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return 0;
  }

  if (!generate_keypair(&x0, &y0, &pub0, group) ||
      !generate_keypair(&x1, &y1, &pub1, group) ||
      !generate_keypair(&xs, &ys, &pubs, group)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_KEYGEN_FAILURE);
    goto err;
  }

  size_t scalar_len = BN_num_bytes(&group->order);
  CBB pub0_cbb, pub1_cbb, pubs_cbb;
  if (!CBB_init_fixed(&cbb, out_priv_key, max_priv_key_len) ||
      !CBB_add_u32(&cbb, id)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  EC_SCALAR *scalars[] = {&x0, &y0, &x1, &y1, &xs, &ys};
  for (size_t i = 0; i < 6; i++) {
    if (!CBB_add_space(&cbb, &buf, scalar_len)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      goto err;
    }
    ec_scalar_to_bytes(group, buf, &scalar_len, scalars[i]);;
  }

  if (!CBB_finish(&cbb, NULL, out_priv_key_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (!CBB_init_fixed(&cbb, out_pub_key, max_pub_key_len) ||
      !CBB_add_u32(&cbb, id)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  size_t pub0_len = EC_POINT_point2oct(
      group, pub0, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
  size_t pub1_len = EC_POINT_point2oct(
      group, pub1, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
  size_t pubs_len = EC_POINT_point2oct(
      group, pubs, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
  if (!CBB_add_u16_length_prefixed(&cbb, &pub0_cbb) ||
      !CBB_add_space(&pub0_cbb, &buf, pub0_len) ||
      EC_POINT_point2oct(group, pub0, POINT_CONVERSION_UNCOMPRESSED, buf,
                         pub0_len, NULL) != pub0_len ||
      !CBB_add_u16_length_prefixed(&cbb, &pub1_cbb) ||
      !CBB_add_space(&pub1_cbb, &buf, pub1_len) ||
      EC_POINT_point2oct(group, pub1, POINT_CONVERSION_UNCOMPRESSED, buf,
                         pub1_len, NULL) != pub1_len ||
      !CBB_add_u16_length_prefixed(&cbb, &pubs_cbb) ||
      !CBB_add_space(&pubs_cbb, &buf, pubs_len) ||
      EC_POINT_point2oct(group, pubs, POINT_CONVERSION_UNCOMPRESSED, buf,
                         pubs_len, NULL) != pubs_len ||
      !CBB_finish(&cbb, NULL, out_pub_key_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  ok = 1;

err:
  EC_POINT_free(pub0);
  EC_POINT_free(pub1);
  EC_POINT_free(pubs);
  return ok;
}
