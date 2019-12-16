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
#include <openssl/rand.h>
#include <openssl/trust_token.h>

#include "../fipsmodule/bn/internal.h"
#include "../fipsmodule/ec/internal.h"

#include "internal.h"


// get_h returns a randomly selected point for the Privacy Pass protocol.
//
// x: 66591746412783875033873351891229753622964683369847172829242944646280287810
//    81195403447871073952234683395256591180452378091073292247502091640572714366
//    588045092
// y: 12347430519393087872533727997980072129796839266949808299436682045034861065
//    18810630511924722292325611253427311923464047364545304196431830383014967865
//    162306253
//
// This point was generated with the following Python code.

/*
import hashlib

SEED_H = 'PrivacyPass H'

A = -3
B = 0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
P = 2**521 - 1

def get_y(x):
  y2 = (x**3 + A*x + B) % P
  y = pow(y2, (P+1)/4, P)
  if (y*y) % P != y2:
    raise ValueError("point not on curve")
  return y

def bit(h,i):
  return (ord(h[i/8]) >> (i%8)) & 1

b = 521
def decode_point(so):
  s = hashlib.sha256(so + '0').digest() + hashlib.sha256(so + '1').digest() + \
      hashlib.sha256(so + '2').digest()

  x = 0
  for i in range(0,b):
    x = x + (long(bit(s,i))<<i)
  if x >= P:
    raise ValueError("x out of range")
  y = get_y(x)
  if y & 1 != bit(s,b-1): y = P-y
  return (x, y)


def gen_point(seed):
  v = hashlib.sha256(seed).digest()
  it = 1
  while True:
    try:
      x,y = decode_point(v)
    except Exception, e:
      print e
      it += 1
      v = hashlib.sha256(v).digest()
      continue
    print "Found in %d iterations:" % it
    print "  x = %d" % x
    print "  y = %d" % y
    print " Encoded (hex): (%x, %x)" % (x, y)
    return (x, y)

if __name__ == "__main__":
  gen_point(SEED_H)
*/

static const uint8_t kDefaultAdditionalData[32] = {0};

static EC_POINT *get_h(void) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return NULL;
  }

  static const BN_ULONG kHGenX[] = {
      TOBN(0x3d01749f, 0xc51e4724),
      TOBN(0x31c28621, 0xf95c98b9),
      TOBN(0x6dc5392a, 0xd4ce846e),
      TOBN(0xda645354, 0x4ef9760d),
      TOBN(0x5945d13e, 0x25337e4c),
      TOBN(0xeb0f6bc0, 0x5c0ecefe),
      TOBN(0xab291003, 0x6f4ef5bd),
      TOBN(0xa9f79ebc, 0x126cefd1),
      0x000001f0,
  };
  static const BIGNUM kX = STATIC_BIGNUM(kHGenX);

  static const BN_ULONG kHGenY[] = {
      TOBN(0xffa6a0ea, 0x966792cd),
      TOBN(0x6e783d17, 0x08e3df3c),
      TOBN(0xb5617012, 0x72ac6ab0),
      TOBN(0xe0bcf350, 0x5c7e6641),
      TOBN(0x53bc55ea, 0xad8f261d),
      TOBN(0xbba93b9d, 0x70491eb4),
      TOBN(0x5214756f, 0x36d9c7fa),
      TOBN(0x1762517d, 0x325e29ac),
      0x0000005c,
  };
  static const BIGNUM kY = STATIC_BIGNUM(kHGenY);

  EC_POINT *h = EC_POINT_new(group);
  if (h == NULL ||
      !EC_POINT_set_affine_coordinates_GFp(group, h, &kX, &kY, NULL)) {
    EC_POINT_free(h);
    return NULL;
  }
  return h;
}

// generate_keypair generates a keypair for the Private Metadata construction.
// |out_x| and |out_y| are set to the secret half of the keypair, while
// |*out_pub| is set to the public half of the keypair. It returns one on
// success and zero on failure.
static int generate_keypair(EC_SCALAR *out_x, EC_SCALAR *out_y,
                            EC_POINT **out_pub, const EC_GROUP *group) {
  EC_POINT *h = get_h();
  if (h == NULL) {
    return 0;
  }

  EC_RAW_POINT tmp1, tmp2;
  EC_POINT *pub = EC_POINT_new(group);
  if (pub == NULL ||
      !ec_random_nonzero_scalar(group, out_x, kDefaultAdditionalData) ||
      !ec_random_nonzero_scalar(group, out_y, kDefaultAdditionalData) ||
      !ec_point_mul_scalar_base(group, &tmp1, out_x) ||
      !ec_point_mul_scalar(group, &tmp2, &h->raw, out_y)) {
    EC_POINT_free(h);
    EC_POINT_free(pub);
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  group->meth->add(group, &pub->raw, &tmp1, &tmp2);
  *out_pub = pub;

  EC_POINT_free(h);
  return 1;
}

int TRUST_TOKEN_generate_key(uint8_t *out_priv_key, size_t *out_priv_key_len,
                             size_t max_priv_key_len, uint8_t *out_pub_key,
                             size_t *out_pub_key_len, size_t max_pub_key_len,
                             uint32_t id) {
  int ok = 0;
  EC_POINT *pub0 = NULL, *pub1 = NULL, *pubs = NULL;
  CBB cbb;
  CBB_zero(&cbb);
  uint8_t *buf = NULL;
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return 0;
  }

  EC_SCALAR x0, y0, x1, y1, xs, ys;
  if (!generate_keypair(&x0, &y0, &pub0, group) ||
      !generate_keypair(&x1, &y1, &pub1, group) ||
      !generate_keypair(&xs, &ys, &pubs, group)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_KEYGEN_FAILURE);
    goto err;
  }

  size_t scalar_len = BN_num_bytes(&group->order);
  if (!CBB_init_fixed(&cbb, out_priv_key, max_priv_key_len) ||
      !CBB_add_u32(&cbb, id)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_BUFFER_TOO_SMALL);
    goto err;
  }

  const EC_SCALAR *scalars[] = {&x0, &y0, &x1, &y1, &xs, &ys};
  for (size_t i = 0; i < OPENSSL_ARRAY_SIZE(scalars); i++) {
    if (!CBB_add_space(&cbb, &buf, scalar_len)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_BUFFER_TOO_SMALL);
      goto err;
    }
    ec_scalar_to_bytes(group, buf, &scalar_len, scalars[i]);
  }

  if (!CBB_finish(&cbb, NULL, out_priv_key_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_BUFFER_TOO_SMALL);
    goto err;
  }

  CBB pub_cbb;
  if (!CBB_init_fixed(&cbb, out_pub_key, max_pub_key_len) ||
      !CBB_add_u32(&cbb, id) ||
      !CBB_add_u16_length_prefixed(&cbb, &pub_cbb) ||
      !EC_POINT_point2cbb(&pub_cbb, group, pub0, POINT_CONVERSION_UNCOMPRESSED,
                          NULL) ||
      !CBB_add_u16_length_prefixed(&cbb, &pub_cbb) ||
      !EC_POINT_point2cbb(&pub_cbb, group, pub1, POINT_CONVERSION_UNCOMPRESSED,
                          NULL) ||
      !CBB_add_u16_length_prefixed(&cbb, &pub_cbb) ||
      !EC_POINT_point2cbb(&pub_cbb, group, pubs, POINT_CONVERSION_UNCOMPRESSED,
                          NULL) ||
      !CBB_finish(&cbb, NULL, out_pub_key_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_BUFFER_TOO_SMALL);
    goto err;
  }

  ok = 1;

err:
  CBB_cleanup(&cbb);
  EC_POINT_free(pub0);
  EC_POINT_free(pub1);
  EC_POINT_free(pubs);
  return ok;
}

void PMBTOKEN_PRETOKEN_free(PMBTOKEN_PRETOKEN *pretoken) {
  OPENSSL_free(pretoken);
}

void PMBTOKEN_TOKEN_free(PMBTOKEN_TOKEN *token) {
  OPENSSL_free(token);
}

static int hash_to_curve(EC_GROUP *group, EC_RAW_POINT *out, uint8_t *in, size_t len) {
/* Steps: */
/* 1. u = hash_to_field(msg, 2) */
/* 2. Q0 = map_to_curve(u[0]) */
/* 3. Q1 = map_to_curve(u[1]) */
/* 4. R = Q0 + Q1              # Point addition */
/* 5. P = clear_cofactor(R) */
/* 6. return P */
  *out = get_h()->raw;
  return 1;
}

static int hash_t(EC_GROUP *group, EC_RAW_POINT *out,
                  uint8_t t[PMBTOKEN_NONCE_SIZE]) {
  uint8_t buf[PMBTOKEN_NONCE_SIZE + 6] = "HashT ";
  OPENSSL_memcpy(buf+6, t, PMBTOKEN_NONCE_SIZE);
  return hash_to_curve(group, out, buf, sizeof(buf));
}

static int hash_s(EC_GROUP *group, EC_RAW_POINT *out, EC_RAW_POINT t,
                  uint8_t s[PMBTOKEN_NONCE_SIZE]) {
  EC_POINT *tmp = EC_POINT_new(group);
  if (tmp == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  int ok = 1;
  tmp->raw = t;
  CBB cbb, tmp_cbb;
  uint8_t *buf;
  size_t len;
  if (!CBB_init(&cbb, 0) ||
      !CBB_add_bytes(&cbb, (uint8_t*)"HashS ", 6) ||
      !CBB_add_u16_length_prefixed(&cbb, &tmp_cbb) ||
      !EC_POINT_point2cbb(&tmp_cbb, group, tmp, POINT_CONVERSION_UNCOMPRESSED,
                          NULL) ||
      !CBB_add_bytes(&cbb, s, PMBTOKEN_NONCE_SIZE) ||
      !CBB_finish(&cbb, &buf, &len) ||
      !hash_to_curve(group, out, buf, len)) {
    ok = 0;
  }

  EC_POINT_free(tmp);
  OPENSSL_free(buf);
  return ok;
}

int pmbtoken_blind(TRUST_TOKEN_CLIENT *ctx, PMBTOKEN_PRETOKEN **out_pretoken) {
  PMBTOKEN_PRETOKEN *pretoken =
      (PMBTOKEN_PRETOKEN *)OPENSSL_malloc(sizeof(PMBTOKEN_PRETOKEN));
  if (pretoken == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  RAND_bytes(pretoken->t, sizeof(pretoken->t));
  if (!ec_random_nonzero_scalar(ctx->group, &pretoken->r,
                                kDefaultAdditionalData)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  EC_SCALAR rtmp, rinv;
  ec_scalar_to_montgomery(ctx->group, &rtmp, &pretoken->r);
  ec_scalar_inv_montgomery(ctx->group, &rinv, &rtmp);
  ec_scalar_from_montgomery(ctx->group, &rinv, &rinv);

  if (!hash_t(ctx->group, &pretoken->T, pretoken->t)) {
    return 0;
  }

  if (!ec_point_mul_scalar(ctx->group, &pretoken->Tp, &pretoken->T, &rinv)) {
    return 0;
  }

  *out_pretoken = pretoken;
  return 1;
}

int pmbtoken_sign(TRUST_TOKEN_ISSUER *ctx, uint8_t out_s[PMBTOKEN_NONCE_SIZE],
                  EC_RAW_POINT *out_Wp, EC_RAW_POINT *out_Wsp, EC_RAW_POINT Tp) {
  struct trust_token_issuer_key_st key = ctx->keys[ctx->public_metadata];
  EC_SCALAR xb = key.x0;
  EC_SCALAR yb = key.y0;
  if (ctx->private_metadata == 1) {
    xb = key.x1;
    yb = key.y1;
  }

  RAND_bytes(out_s, PMBTOKEN_NONCE_SIZE);

  EC_RAW_POINT Sp;
  if (!hash_s(ctx->group, &Sp, Tp, out_s)) {
    return 0;
  }

  EC_RAW_POINT tmp1, tmp2, tmp3, tmp4;
  if (!ec_point_mul_scalar(ctx->group, &tmp1, &Tp, &xb) ||
      !ec_point_mul_scalar(ctx->group, &tmp2, &Sp, &yb) ||
      !ec_point_mul_scalar(ctx->group, &tmp3, &Tp, &key.xs) ||
      !ec_point_mul_scalar(ctx->group, &tmp4, &Sp, &key.ys)) {
    return 0;
  }

  ctx->group->meth->add(ctx->group, out_Wp, &tmp1, &tmp2);
  ctx->group->meth->add(ctx->group, out_Wsp, &tmp3, &tmp4);

  // TODO: DLEQ Proofs
  return 1;
}

int pmbtoken_unblind(TRUST_TOKEN_CLIENT *ctx, PMBTOKEN_TOKEN **out_token,
                     uint8_t s[PMBTOKEN_NONCE_SIZE], EC_RAW_POINT Wp,
                     EC_RAW_POINT Wsp, PMBTOKEN_PRETOKEN *pretoken) {
  PMBTOKEN_TOKEN *token =
      (PMBTOKEN_TOKEN *)OPENSSL_malloc(sizeof(PMBTOKEN_TOKEN));
  if (token == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  // TODO: Check DLEQ Proofs

  EC_RAW_POINT Sp;
  if (!hash_s(ctx->group, &Sp, pretoken->Tp, s)) {
    return 0;
  }

  OPENSSL_memcpy(token->t, pretoken->t, PMBTOKEN_NONCE_SIZE);
  if (!ec_point_mul_scalar(ctx->group, &token->S, &Sp, &pretoken->r) ||
      !ec_point_mul_scalar(ctx->group, &token->W, &Wp, &pretoken->r) ||
      !ec_point_mul_scalar(ctx->group, &token->Ws, &Wsp, &pretoken->r)) {
    return 0;
  }

  *out_token = token;
  return 1;
}

int pmbtoken_read(TRUST_TOKEN_ISSUER *ctx, uint8_t *out_result,
                  uint8_t *out_private_metadata, PMBTOKEN_TOKEN *token,
                  uint8_t public_metadata) {
  struct trust_token_issuer_key_st key = ctx->keys[public_metadata];

  EC_RAW_POINT T;
  if (!hash_t(ctx->group, &T, token->t)) {
    return 0;
  }

  EC_RAW_POINT tmp1, tmp2, calculated;
  if (!ec_point_mul_scalar(ctx->group, &tmp1, &T, &key.xs) ||
      !ec_point_mul_scalar(ctx->group, &tmp2, &token->S, &key.ys)) {
    return 0;
  }

  ctx->group->meth->add(ctx->group, &calculated, &tmp1, &tmp2);

  if (ec_GFp_simple_cmp(ctx->group, &calculated, &token->Ws) != 0) {
    *out_result = 0;
    return 1;
  }
  *out_result = 1;
  if (!ec_point_mul_scalar(ctx->group, &tmp1, &T, &key.x0) ||
      !ec_point_mul_scalar(ctx->group, &tmp2, &token->S, &key.y0)) {
    return 0;
  }

  ctx->group->meth->add(ctx->group, &calculated, &tmp1, &tmp2);
  if (ec_GFp_simple_cmp(ctx->group, &calculated, &token->W) == 0) {
    *out_private_metadata = 0;
    return 1;
  }

  if (!ec_point_mul_scalar(ctx->group, &tmp1, &T, &key.x1) ||
      !ec_point_mul_scalar(ctx->group, &tmp2, &token->S, &key.y1)) {
    return 0;
  }

  ctx->group->meth->add(ctx->group, &calculated, &tmp1, &tmp2);
  if (ec_GFp_simple_cmp(ctx->group, &calculated, &token->W) == 0) {
    *out_private_metadata = 1;
    return 1;
  }

  return 0;
}
