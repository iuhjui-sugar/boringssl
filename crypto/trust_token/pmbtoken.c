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
#include <openssl/sha.h>
#include <openssl/trust_token.h>

#include "../fipsmodule/bn/internal.h"
#include "../fipsmodule/ec/internal.h"

#include "internal.h"


// get_h returns the generator H for PMBTokens.
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

// generate_keypair generates a keypair for the PMBTokens construction.
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

// TODO: Implement real HashToCurve.
static int hash_to_curve(EC_GROUP *group, EC_RAW_POINT *out, uint8_t *in,
                         size_t len) {
  uint8_t hash_buf[128];

  SHA512_CTX sha;
  SHA512_Init(&sha);
  SHA512_Update(&sha, "HTC1", 4);
  SHA512_Update(&sha, in, len);
  SHA512_Final(hash_buf, &sha);
  SHA512_Init(&sha);
  SHA512_Update(&sha, "HTC2", 4);
  SHA512_Update(&sha, in, len);
  SHA512_Final(hash_buf + 64, &sha);

  BN_CTX *ctx = BN_CTX_new();
  EC_POINT *tmp = EC_POINT_new(group);
  if (ctx == NULL || tmp == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  int ok = 0;
  BN_CTX_start(ctx);

  BIGNUM *u = BN_bin2bn(hash_buf, sizeof(hash_buf), NULL);
  BN_rshift(u, u, (8*sizeof(hash_buf))-EC_GROUP_order_bits(group));

  BIGNUM *zero = BN_CTX_get(ctx);
  BN_zero(zero);
  BIGNUM *one = BN_CTX_get(ctx);
  BN_one(one);

  BIGNUM *p = BN_CTX_get(ctx);
  BN_one(p);
  BN_lshift(p, p, 521);
  BN_sub_word(p, 1);

  BIGNUM *A = BN_CTX_get(ctx);
  if (!BN_set_word(A, 3)) {
    goto err;
  }
  BN_set_negative(A, 1);

  static const BN_ULONG kP521B[] = {
    TOBN(0xef451fd4, 0x6b503f00),
    TOBN(0x3573df88, 0x3d2c34f1),
    TOBN(0x1652c0bd, 0x3bb1bf07),
    TOBN(0x56193951, 0xec7e937b),
    TOBN(0xb8b48991, 0x8ef109e1),
    TOBN(0xa2da725b, 0x99b315f3),
    TOBN(0x929a21a0, 0xb68540ee),
    TOBN(0x953eb961, 0x8e1c9a1f),
    0x00000051,
  };

  static const BIGNUM B = STATIC_BIGNUM(kP521B);

  BIGNUM *Z = BN_CTX_get(ctx);
  if (!BN_set_word(Z, 4)) {
    goto err;
  }
  BN_set_negative(Z, 1);

  BIGNUM *Ainv = BN_CTX_get(ctx);
  BIGNUM *Zinv = BN_CTX_get(ctx);
  BIGNUM *c1 = BN_CTX_get(ctx);
  BIGNUM *c2 = BN_CTX_get(ctx);
  BIGNUM *u2 = BN_CTX_get(ctx);
  BIGNUM *tv1 = BN_CTX_get(ctx);
  BIGNUM *tv2 = BN_CTX_get(ctx);
  BIGNUM *x1 = BN_CTX_get(ctx);
  BIGNUM *gx1 = BN_CTX_get(ctx);
  BIGNUM *x2 = BN_CTX_get(ctx);
  BIGNUM *gx2 = BN_CTX_get(ctx);
  BIGNUM *x = BN_CTX_get(ctx);

  if (BN_mod_inverse(Ainv, A, p, ctx) == NULL ||
      BN_mod_inverse(Zinv, Z, p, ctx) == NULL ||
      !BN_mod_sub(c1, zero, &B, p, ctx) ||
      !BN_mod_mul(c1, c1, Ainv, p, ctx) ||
      !BN_mod_sub(c2, zero, one, p, ctx) ||
      !BN_mod_mul(c2, c2, Zinv, p, ctx) ||
      !BN_mod_sqr(u2, u, p, ctx) ||
      !BN_mod_mul(tv1, Z, u2, p, ctx) ||
      !BN_mod_sqr(tv2, tv1, p, ctx) ||
      !BN_mod_add(x1, tv1, tv2, p, ctx) ||
      BN_mod_inverse(x1, x1, p, ctx) == NULL) {
    goto err;
  }

  if (BN_is_zero(x1)) {
    x1 = c2;
  } else {
    if (!BN_mod_add(x1, x1, one, p, ctx)) {
      goto err;
    }
  }

  if (!BN_mod_mul(x1, x1, c1, p, ctx) ||
      !BN_mod_sqr(gx1, x1, p, ctx) ||
      !BN_mod_add(gx1, gx1, A, p, ctx) ||
      !BN_mod_mul(gx1, gx1, x1, p, ctx) ||
      !BN_mod_add(gx1, gx1, &B, p, ctx) ||
      !BN_mod_mul(x2, tv1, x1, p, ctx) ||
      !BN_mod_mul(tv2, tv1, tv2, p, ctx) ||
      !BN_mod_mul(gx2, gx1, tv2, p, ctx)) {
    goto err;
  }

  ERR_set_mark();
  BIGNUM *y = BN_mod_sqrt(NULL, gx1, p, ctx);
  if (y == NULL) {
    ERR_pop_to_mark();
    x = x2;
    y = BN_mod_sqrt(y, gx2, p, ctx);
    if (y == NULL) {
      goto err;
    }
  } else {
    x = x1;
  }

  BN_set_negative(y, BN_is_negative(u));

  if (!EC_POINT_set_affine_coordinates_GFp(group, tmp, x, y, NULL)) {
    goto err;
  }

  *out = tmp->raw;
  ok = 1;

err:
  BN_CTX_end(ctx);
  EC_POINT_free(tmp);
  return ok;
}

// hash_t implements the H_t operation in PMBTokens. It returns on on success
// and zero on error.
static int hash_t(EC_GROUP *group, EC_RAW_POINT *out,
                  const uint8_t t[PMBTOKEN_NONCE_SIZE]) {
  uint8_t buf[PMBTOKEN_NONCE_SIZE + 6] = "HashT ";
  OPENSSL_memcpy(buf+6, t, PMBTOKEN_NONCE_SIZE);
  return hash_to_curve(group, out, buf, sizeof(buf));
}

// hash_s implements the H_s operation in PMBTokens. It returns on on success
// and zero on error.
static int hash_s(EC_GROUP *group, EC_RAW_POINT *out, const EC_RAW_POINT *t,
                  const uint8_t s[PMBTOKEN_NONCE_SIZE]) {
  EC_POINT *tmp = EC_POINT_new(group);
  if (tmp == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  int ok = 1;
  tmp->raw = *t;
  CBB cbb, tmp_cbb;
  uint8_t *buf = NULL;
  size_t len;
  if (!CBB_init(&cbb, 0) ||
      !CBB_add_bytes(&cbb, (uint8_t*)"HashS ", 6) ||
      !CBB_add_u16_length_prefixed(&cbb, &tmp_cbb) ||
      !EC_POINT_point2cbb(&tmp_cbb, group, tmp, POINT_CONVERSION_UNCOMPRESSED,
                          NULL) ||
      !CBB_add_bytes(&cbb, s, PMBTOKEN_NONCE_SIZE) ||
      !CBB_finish(&cbb, &buf, &len) ||
      !hash_to_curve(group, out, buf, len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    ok = 0;
  }

  EC_POINT_free(tmp);
  OPENSSL_free(buf);
  CBB_cleanup(&cbb);
  return ok;
}

PMBTOKEN_PRETOKEN *pmbtoken_blind(void) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return NULL;
  }

  PMBTOKEN_PRETOKEN *pretoken = OPENSSL_malloc(sizeof(PMBTOKEN_PRETOKEN));
  if (pretoken == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  RAND_bytes(pretoken->t, sizeof(pretoken->t));

  // We sample |pretoken->r| in Montgomery form to simplify inverting.
  if (!ec_random_nonzero_scalar(group, &pretoken->r,
                                kDefaultAdditionalData)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  EC_SCALAR rinv;
  ec_scalar_inv_montgomery(group, &rinv, &pretoken->r);
  // Convert both out of Montgomery form.
  ec_scalar_from_montgomery(group, &pretoken->r, &pretoken->r);
  ec_scalar_from_montgomery(group, &rinv, &rinv);

  if (!hash_t(group, &pretoken->T, pretoken->t)) {
    return NULL;
  }

  if (!ec_point_mul_scalar(group, &pretoken->Tp, &pretoken->T, &rinv)) {
    return NULL;
  }

  return pretoken;
}

int pmbtoken_sign(TRUST_TOKEN_ISSUER *ctx, uint8_t out_s[PMBTOKEN_NONCE_SIZE],
                  EC_RAW_POINT *out_Wp, EC_RAW_POINT *out_Wsp,
                  const EC_RAW_POINT *Tp) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return 0;
  }

  if (ctx->num_keys == 0) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_NO_KEYS_CONFIGURED);
    return 0;
  }
  const struct trust_token_issuer_key_st *key = &ctx->keys[0];
  for (size_t i = 0; i < ctx->num_keys; i++) {
    if (ctx->keys[i].id == ctx->public_metadata) {
      key = &ctx->keys[i];
    }
  }

  EC_SCALAR xb, yb;
  BN_ULONG mask = ctx->private_metadata*((BN_ULONG)-1);
  ec_scalar_select(group, &xb, mask, &key->x1, &key->x0);
  ec_scalar_select(group, &yb, mask, &key->y1, &key->y0);

  RAND_bytes(out_s, PMBTOKEN_NONCE_SIZE);

  EC_RAW_POINT Sp;
  if (!hash_s(group, &Sp, Tp, out_s)) {
    return 0;
  }

  EC_RAW_POINT tmp1, tmp2, tmp3, tmp4;
  if (!ec_point_mul_scalar(group, &tmp1, Tp, &xb) ||
      !ec_point_mul_scalar(group, &tmp2, &Sp, &yb) ||
      !ec_point_mul_scalar(group, &tmp3, Tp, &key->xs) ||
      !ec_point_mul_scalar(group, &tmp4, &Sp, &key->ys)) {
    return 0;
  }

  group->meth->add(group, out_Wp, &tmp1, &tmp2);
  group->meth->add(group, out_Wsp, &tmp3, &tmp4);

  // TODO: DLEQ Proofs
  return 1;
}

PMBTOKEN_TOKEN *pmbtoken_unblind(const uint8_t s[PMBTOKEN_NONCE_SIZE],
                                 const EC_RAW_POINT *Wp,
                                 const EC_RAW_POINT *Wsp,
                                 const PMBTOKEN_PRETOKEN *pretoken) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return NULL;
  }

  PMBTOKEN_TOKEN *token = OPENSSL_malloc(sizeof(PMBTOKEN_TOKEN));
  if (token == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  // TODO: Check DLEQ Proofs

  EC_RAW_POINT Sp;
  if (!hash_s(group, &Sp, &pretoken->Tp, s)) {
    return NULL;
  }

  OPENSSL_memcpy(token->t, pretoken->t, PMBTOKEN_NONCE_SIZE);
  if (!ec_point_mul_scalar(group, &token->S, &Sp, &pretoken->r) ||
      !ec_point_mul_scalar(group, &token->W, Wp, &pretoken->r) ||
      !ec_point_mul_scalar(group, &token->Ws, Wsp, &pretoken->r)) {
    return NULL;
  }

  return token;
}

static int check_scalar_mul(const EC_GROUP *group, const EC_RAW_POINT *value,
                            const EC_RAW_POINT *g, const EC_SCALAR *g_scalar,
                            const EC_RAW_POINT *p, const EC_SCALAR *p_scalar) {
  EC_RAW_POINT tmp1, tmp2, r;
  if (!ec_point_mul_scalar(group, &tmp1, g, g_scalar) ||
      !ec_point_mul_scalar(group, &tmp2, p, p_scalar)) {
    return 0;
  }

  group->meth->add(group, &r, &tmp1, &tmp2);
  return ec_GFp_simple_cmp(group, &r, value) == 0;
}

int pmbtoken_read(TRUST_TOKEN_ISSUER *ctx, uint8_t *out_private_metadata,
                  const PMBTOKEN_TOKEN *token, uint32_t public_metadata) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return 0;
  }

  if (ctx->num_keys == 0) {
    return 0;
  }
  struct trust_token_issuer_key_st key = ctx->keys[0];
  for (size_t index = 0; index < ctx->num_keys; index++) {
    if (ctx->keys[index].id == public_metadata) {
      key = ctx->keys[index];
    }
  }

  EC_RAW_POINT T;
  if (!hash_t(group, &T, token->t)) {
    return 0;
  }

  // Check the validity of the token.
  if (!check_scalar_mul(group, &token->Ws, &T, &key.xs, &token->S, &key.ys)) {
    return 0;
  }

  // An invalid private metadata bit defaults to '2'.
  *out_private_metadata = 2;

  // Compare the private metadata bit against a value of '0'.
  if (check_scalar_mul(group, &token->W, &T, &key.x0, &token->S, &key.y0)) {
    *out_private_metadata = 0;
  }

  // Compare the private metadata bit against a value of '1'.
  if (check_scalar_mul(group, &token->W, &T, &key.x1, &token->S, &key.y1)) {
    *out_private_metadata = 1;
  }

  return 1;
}
