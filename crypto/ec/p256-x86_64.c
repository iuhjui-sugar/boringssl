/******************************************************************************
 *                                                                            *
 * Copyright 2014 Intel Corporation                                           *
 *                                                                            *
 * Licensed under the Apache License, Version 2.0 (the "License");            *
 * you may not use this file except in compliance with the License.           *
 * You may obtain a copy of the License at                                    *
 *                                                                            *
 *    http://www.apache.org/licenses/LICENSE-2.0                              *
 *                                                                            *
 * Unless required by applicable law or agreed to in writing, software        *
 * distributed under the License is distributed on an "AS IS" BASIS,          *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   *
 * See the License for the specific language governing permissions and        *
 * limitations under the License.                                             *
 *                                                                            *
 ******************************************************************************
 *                                                                            *
 * Developers and authors:                                                    *
 * Shay Gueron (1, 2), and Vlad Krasnov (1)                                   *
 * (1) Intel Corporation, Israel Development Center                           *
 * (2) University of Haifa                                                    *
 * Reference:                                                                 *
 * S.Gueron and V.Krasnov, "Fast Prime Field Elliptic Curve Cryptography with *
 *                          256 Bit Primes"                                   *
 *                                                                            *
 ******************************************************************************/

#include <openssl/ec.h>

#include <stdint.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "../bn/internal.h"
#include "../ec/internal.h"
#include "../internal.h"


#if !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86_64) && \
    !defined(OPENSSL_SMALL)

#if BN_BITS2 != 64
#define TOBN(hi, lo) lo, hi
#else
#define TOBN(hi, lo) ((BN_ULONG)hi << 32 | lo)
#endif

#if defined(__GNUC__)
#define ALIGN32 __attribute((aligned(32)))
#elif defined(_MSC_VER)
#define ALIGN32 __declspec(align(32))
#else
#define ALIGN32
#endif

#define ALIGNPTR(p, N) ((unsigned char *)p + N - (size_t)p % N)
#define P256_LIMBS (256 / BN_BITS2)

typedef uint16_t u16;

typedef struct {
  BN_ULONG X[P256_LIMBS];
  BN_ULONG Y[P256_LIMBS];
  BN_ULONG Z[P256_LIMBS];
} P256_POINT;

typedef struct {
  BN_ULONG X[P256_LIMBS];
  BN_ULONG Y[P256_LIMBS];
} P256_POINT_AFFINE;

typedef P256_POINT_AFFINE PRECOMP256_ROW[64];

/* structure for precomputed multiples of the generator */

/* Functions implemented in assembly */
/* Modular mul by 2: res = 2*a mod P */
void ecp_nistz256_mul_by_2(BN_ULONG res[P256_LIMBS],
                           const BN_ULONG a[P256_LIMBS]);
/* Modular div by 2: res = a/2 mod P */
void ecp_nistz256_div_by_2(BN_ULONG res[P256_LIMBS],
                           const BN_ULONG a[P256_LIMBS]);
/* Modular mul by 3: res = 3*a mod P */
void ecp_nistz256_mul_by_3(BN_ULONG res[P256_LIMBS],
                           const BN_ULONG a[P256_LIMBS]);
/* Modular add: res = a+b mod P */
void ecp_nistz256_add(BN_ULONG res[P256_LIMBS], const BN_ULONG a[P256_LIMBS],
                      const BN_ULONG b[P256_LIMBS]);
/* Modular sub: res = a-b mod P */
void ecp_nistz256_sub(BN_ULONG res[P256_LIMBS], const BN_ULONG a[P256_LIMBS],
                      const BN_ULONG b[P256_LIMBS]);
/* Modular neg: res = -a mod P */
void ecp_nistz256_neg(BN_ULONG res[P256_LIMBS], const BN_ULONG a[P256_LIMBS]);
/* Montgomery mul: res = a*b*2^-256 mod P */
void ecp_nistz256_mul_mont(BN_ULONG res[P256_LIMBS],
                           const BN_ULONG a[P256_LIMBS],
                           const BN_ULONG b[P256_LIMBS]);
/* Montgomery sqr: res = a*a*2^-256 mod P */
void ecp_nistz256_sqr_mont(BN_ULONG res[P256_LIMBS],
                           const BN_ULONG a[P256_LIMBS]);
/* Convert a number from Montgomery domain, by multiplying with 1 */
void ecp_nistz256_from_mont(BN_ULONG res[P256_LIMBS],
                            const BN_ULONG in[P256_LIMBS]);
/* Convert a number to Montgomery domain, by multiplying with 2^512 mod P*/
void ecp_nistz256_to_mont(BN_ULONG res[P256_LIMBS],
                          const BN_ULONG in[P256_LIMBS]);
/* Functions that perform constant time access to the precomputed tables */
void ecp_nistz256_select_w5(P256_POINT *val, const P256_POINT *in_t, int index);
void ecp_nistz256_select_w7(P256_POINT_AFFINE *val,
                            const P256_POINT_AFFINE *in_t, int index);

/* One converted into the Montgomery domain */
static const BN_ULONG ONE[P256_LIMBS] = {
    TOBN(0x00000000, 0x00000001), TOBN(0xffffffff, 0x00000000),
    TOBN(0xffffffff, 0xffffffff), TOBN(0x00000000, 0xfffffffe),
};


/* Precomputed tables for the default generator */
#include "ecp_nistz256_table.h"

/* Recode window to a signed digit, see ecp_nistputil.c for details */
static unsigned int booth_recode_w5(unsigned int in) {
  unsigned s, d;

  s = ~((in >> 5) - 1);
  d = (1 << 6) - in - 1;
  d = (d & s) | (in & ~s);
  d = (d >> 1) + (d & 1);

  return (d << 1) + (s & 1);
}

static unsigned int booth_recode_w7(unsigned int in) {
  unsigned s, d;

  s = ~((in >> 7) - 1);
  d = (1 << 8) - in - 1;
  d = (d & s) | (in & ~s);
  d = (d >> 1) + (d & 1);

  return (d << 1) + (s & 1);
}

static void copy_conditional(BN_ULONG dst[P256_LIMBS],
                             const BN_ULONG src[P256_LIMBS], BN_ULONG move) {
  BN_ULONG mask1 = -move;
  BN_ULONG mask2 = ~mask1;

  dst[0] = (src[0] & mask1) ^ (dst[0] & mask2);
  dst[1] = (src[1] & mask1) ^ (dst[1] & mask2);
  dst[2] = (src[2] & mask1) ^ (dst[2] & mask2);
  dst[3] = (src[3] & mask1) ^ (dst[3] & mask2);
  if (P256_LIMBS == 8) {
    dst[4] = (src[4] & mask1) ^ (dst[4] & mask2);
    dst[5] = (src[5] & mask1) ^ (dst[5] & mask2);
    dst[6] = (src[6] & mask1) ^ (dst[6] & mask2);
    dst[7] = (src[7] & mask1) ^ (dst[7] & mask2);
  }
}

static BN_ULONG is_zero(BN_ULONG in) {
  in |= (0 - in);
  in = ~in;
  in &= BN_MASK2;
  in >>= BN_BITS2 - 1;
  return in;
}

static BN_ULONG is_equal(const BN_ULONG a[P256_LIMBS],
                         const BN_ULONG b[P256_LIMBS]) {
  BN_ULONG res;

  res = a[0] ^ b[0];
  res |= a[1] ^ b[1];
  res |= a[2] ^ b[2];
  res |= a[3] ^ b[3];
  if (P256_LIMBS == 8) {
    res |= a[4] ^ b[4];
    res |= a[5] ^ b[5];
    res |= a[6] ^ b[6];
    res |= a[7] ^ b[7];
  }

  return is_zero(res);
}

static BN_ULONG is_one(const BN_ULONG a[P256_LIMBS]) {
  BN_ULONG res;

  res = a[0] ^ ONE[0];
  res |= a[1] ^ ONE[1];
  res |= a[2] ^ ONE[2];
  res |= a[3] ^ ONE[3];
  if (P256_LIMBS == 8) {
    res |= a[4] ^ ONE[4];
    res |= a[5] ^ ONE[5];
    res |= a[6] ^ ONE[6];
  }

  return is_zero(res);
}

#ifndef ECP_NISTZ256_REFERENCE_IMPLEMENTATION
void ecp_nistz256_point_double(P256_POINT *r, const P256_POINT *a);
void ecp_nistz256_point_add(P256_POINT *r, const P256_POINT *a,
                            const P256_POINT *b);
void ecp_nistz256_point_add_affine(P256_POINT *r, const P256_POINT *a,
                                   const P256_POINT_AFFINE *b);
#else
/* Point double: r = 2*a */
static void ecp_nistz256_point_double(P256_POINT *r, const P256_POINT *a) {
  BN_ULONG S[P256_LIMBS];
  BN_ULONG M[P256_LIMBS];
  BN_ULONG Zsqr[P256_LIMBS];
  BN_ULONG tmp0[P256_LIMBS];

  const BN_ULONG *in_x = a->X;
  const BN_ULONG *in_y = a->Y;
  const BN_ULONG *in_z = a->Z;

  BN_ULONG *res_x = r->X;
  BN_ULONG *res_y = r->Y;
  BN_ULONG *res_z = r->Z;

  ecp_nistz256_mul_by_2(S, in_y);

  ecp_nistz256_sqr_mont(Zsqr, in_z);

  ecp_nistz256_sqr_mont(S, S);

  ecp_nistz256_mul_mont(res_z, in_z, in_y);
  ecp_nistz256_mul_by_2(res_z, res_z);

  ecp_nistz256_add(M, in_x, Zsqr);
  ecp_nistz256_sub(Zsqr, in_x, Zsqr);

  ecp_nistz256_sqr_mont(res_y, S);
  ecp_nistz256_div_by_2(res_y, res_y);

  ecp_nistz256_mul_mont(M, M, Zsqr);
  ecp_nistz256_mul_by_3(M, M);

  ecp_nistz256_mul_mont(S, S, in_x);
  ecp_nistz256_mul_by_2(tmp0, S);

  ecp_nistz256_sqr_mont(res_x, M);

  ecp_nistz256_sub(res_x, res_x, tmp0);
  ecp_nistz256_sub(S, S, res_x);

  ecp_nistz256_mul_mont(S, S, M);
  ecp_nistz256_sub(res_y, S, res_y);
}

/* Point addition: r = a+b */
static void ecp_nistz256_point_add(P256_POINT *r, const P256_POINT *a,
                                   const P256_POINT *b) {
  BN_ULONG U2[P256_LIMBS], S2[P256_LIMBS];
  BN_ULONG U1[P256_LIMBS], S1[P256_LIMBS];
  BN_ULONG Z1sqr[P256_LIMBS];
  BN_ULONG Z2sqr[P256_LIMBS];
  BN_ULONG H[P256_LIMBS], R[P256_LIMBS];
  BN_ULONG Hsqr[P256_LIMBS];
  BN_ULONG Rsqr[P256_LIMBS];
  BN_ULONG Hcub[P256_LIMBS];

  BN_ULONG res_x[P256_LIMBS];
  BN_ULONG res_y[P256_LIMBS];
  BN_ULONG res_z[P256_LIMBS];

  BN_ULONG in1infty, in2infty;

  const BN_ULONG *in1_x = a->X;
  const BN_ULONG *in1_y = a->Y;
  const BN_ULONG *in1_z = a->Z;

  const BN_ULONG *in2_x = b->X;
  const BN_ULONG *in2_y = b->Y;
  const BN_ULONG *in2_z = b->Z;

  /* We encode infinity as (0,0), which is not on the curve,
   * so it is OK. */
  in1infty = in1_x[0] | in1_x[1] | in1_x[2] | in1_x[3] | in1_y[0] | in1_y[1] |
             in1_y[2] | in1_y[3];
  if (P256_LIMBS == 8)
    in1infty |= in1_x[4] | in1_x[5] | in1_x[6] | in1_x[7] | in1_y[4] |
                in1_y[5] | in1_y[6] | in1_y[7];

  in2infty = in2_x[0] | in2_x[1] | in2_x[2] | in2_x[3] | in2_y[0] | in2_y[1] |
             in2_y[2] | in2_y[3];
  if (P256_LIMBS == 8)
    in2infty |= in2_x[4] | in2_x[5] | in2_x[6] | in2_x[7] | in2_y[4] |
                in2_y[5] | in2_y[6] | in2_y[7];

  in1infty = is_zero(in1infty);
  in2infty = is_zero(in2infty);

  ecp_nistz256_sqr_mont(Z2sqr, in2_z); /* Z2^2 */
  ecp_nistz256_sqr_mont(Z1sqr, in1_z); /* Z1^2 */

  ecp_nistz256_mul_mont(S1, Z2sqr, in2_z); /* S1 = Z2^3 */
  ecp_nistz256_mul_mont(S2, Z1sqr, in1_z); /* S2 = Z1^3 */

  ecp_nistz256_mul_mont(S1, S1, in1_y); /* S1 = Y1*Z2^3 */
  ecp_nistz256_mul_mont(S2, S2, in2_y); /* S2 = Y2*Z1^3 */
  ecp_nistz256_sub(R, S2, S1);          /* R = S2 - S1 */

  ecp_nistz256_mul_mont(U1, in1_x, Z2sqr); /* U1 = X1*Z2^2 */
  ecp_nistz256_mul_mont(U2, in2_x, Z1sqr); /* U2 = X2*Z1^2 */
  ecp_nistz256_sub(H, U2, U1);             /* H = U2 - U1 */

  /* This should not happen during sign/ecdh,
   * so no constant time violation */
  if (is_equal(U1, U2) && !in1infty && !in2infty) {
    if (is_equal(S1, S2)) {
      ecp_nistz256_point_double(r, a);
      return;
    } else {
      memset(r, 0, sizeof(*r));
      return;
    }
  }

  ecp_nistz256_sqr_mont(Rsqr, R);             /* R^2 */
  ecp_nistz256_mul_mont(res_z, H, in1_z);     /* Z3 = H*Z1*Z2 */
  ecp_nistz256_sqr_mont(Hsqr, H);             /* H^2 */
  ecp_nistz256_mul_mont(res_z, res_z, in2_z); /* Z3 = H*Z1*Z2 */
  ecp_nistz256_mul_mont(Hcub, Hsqr, H);       /* H^3 */

  ecp_nistz256_mul_mont(U2, U1, Hsqr); /* U1*H^2 */
  ecp_nistz256_mul_by_2(Hsqr, U2);     /* 2*U1*H^2 */

  ecp_nistz256_sub(res_x, Rsqr, Hsqr);
  ecp_nistz256_sub(res_x, res_x, Hcub);

  ecp_nistz256_sub(res_y, U2, res_x);

  ecp_nistz256_mul_mont(S2, S1, Hcub);
  ecp_nistz256_mul_mont(res_y, R, res_y);
  ecp_nistz256_sub(res_y, res_y, S2);

  copy_conditional(res_x, in2_x, in1infty);
  copy_conditional(res_y, in2_y, in1infty);
  copy_conditional(res_z, in2_z, in1infty);

  copy_conditional(res_x, in1_x, in2infty);
  copy_conditional(res_y, in1_y, in2infty);
  copy_conditional(res_z, in1_z, in2infty);

  memcpy(r->X, res_x, sizeof(res_x));
  memcpy(r->Y, res_y, sizeof(res_y));
  memcpy(r->Z, res_z, sizeof(res_z));
}

/* Point addition when b is known to be affine: r = a+b */
static void ecp_nistz256_point_add_affine(P256_POINT *r, const P256_POINT *a,
                                          const P256_POINT_AFFINE *b) {
  BN_ULONG U2[P256_LIMBS], S2[P256_LIMBS];
  BN_ULONG Z1sqr[P256_LIMBS];
  BN_ULONG H[P256_LIMBS], R[P256_LIMBS];
  BN_ULONG Hsqr[P256_LIMBS];
  BN_ULONG Rsqr[P256_LIMBS];
  BN_ULONG Hcub[P256_LIMBS];

  BN_ULONG res_x[P256_LIMBS];
  BN_ULONG res_y[P256_LIMBS];
  BN_ULONG res_z[P256_LIMBS];

  BN_ULONG in1infty, in2infty;

  const BN_ULONG *in1_x = a->X;
  const BN_ULONG *in1_y = a->Y;
  const BN_ULONG *in1_z = a->Z;

  const BN_ULONG *in2_x = b->X;
  const BN_ULONG *in2_y = b->Y;

  /* In affine representation we encode infty as (0,0),
   * which is not on the curve, so it is OK */
  in1infty = in1_x[0] | in1_x[1] | in1_x[2] | in1_x[3] | in1_y[0] | in1_y[1] |
             in1_y[2] | in1_y[3];
  if (P256_LIMBS == 8) {
    in1infty |= in1_x[4] | in1_x[5] | in1_x[6] | in1_x[7] | in1_y[4] |
                in1_y[5] | in1_y[6] | in1_y[7];
  }

  in2infty = in2_x[0] | in2_x[1] | in2_x[2] | in2_x[3] | in2_y[0] | in2_y[1] |
             in2_y[2] | in2_y[3];
  if (P256_LIMBS == 8) {
    in2infty |= in2_x[4] | in2_x[5] | in2_x[6] | in2_x[7] | in2_y[4] |
                in2_y[5] | in2_y[6] | in2_y[7];
  }

  in1infty = is_zero(in1infty);
  in2infty = is_zero(in2infty);

  ecp_nistz256_sqr_mont(Z1sqr, in1_z); /* Z1^2 */

  ecp_nistz256_mul_mont(U2, in2_x, Z1sqr); /* U2 = X2*Z1^2 */
  ecp_nistz256_sub(H, U2, in1_x);          /* H = U2 - U1 */

  ecp_nistz256_mul_mont(S2, Z1sqr, in1_z); /* S2 = Z1^3 */

  ecp_nistz256_mul_mont(res_z, H, in1_z); /* Z3 = H*Z1*Z2 */

  ecp_nistz256_mul_mont(S2, S2, in2_y); /* S2 = Y2*Z1^3 */
  ecp_nistz256_sub(R, S2, in1_y);       /* R = S2 - S1 */

  ecp_nistz256_sqr_mont(Hsqr, H);       /* H^2 */
  ecp_nistz256_sqr_mont(Rsqr, R);       /* R^2 */
  ecp_nistz256_mul_mont(Hcub, Hsqr, H); /* H^3 */

  ecp_nistz256_mul_mont(U2, in1_x, Hsqr); /* U1*H^2 */
  ecp_nistz256_mul_by_2(Hsqr, U2);        /* 2*U1*H^2 */

  ecp_nistz256_sub(res_x, Rsqr, Hsqr);
  ecp_nistz256_sub(res_x, res_x, Hcub);
  ecp_nistz256_sub(H, U2, res_x);

  ecp_nistz256_mul_mont(S2, in1_y, Hcub);
  ecp_nistz256_mul_mont(H, H, R);
  ecp_nistz256_sub(res_y, H, S2);

  copy_conditional(res_x, in2_x, in1infty);
  copy_conditional(res_x, in1_x, in2infty);

  copy_conditional(res_y, in2_y, in1infty);
  copy_conditional(res_y, in1_y, in2infty);

  copy_conditional(res_z, ONE, in1infty);
  copy_conditional(res_z, in1_z, in2infty);

  memcpy(r->X, res_x, sizeof(res_x));
  memcpy(r->Y, res_y, sizeof(res_y));
  memcpy(r->Z, res_z, sizeof(res_z));
}
#endif

/* r = in^-1 mod p */
static void ecp_nistz256_mod_inverse(BN_ULONG r[P256_LIMBS],
                                     const BN_ULONG in[P256_LIMBS]) {
  /* The poly is ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff
     ffffffff
     We use FLT and used poly-2 as exponent */
  BN_ULONG p2[P256_LIMBS];
  BN_ULONG p4[P256_LIMBS];
  BN_ULONG p8[P256_LIMBS];
  BN_ULONG p16[P256_LIMBS];
  BN_ULONG p32[P256_LIMBS];
  BN_ULONG res[P256_LIMBS];
  int i;

  ecp_nistz256_sqr_mont(res, in);
  ecp_nistz256_mul_mont(p2, res, in); /* 3*p */

  ecp_nistz256_sqr_mont(res, p2);
  ecp_nistz256_sqr_mont(res, res);
  ecp_nistz256_mul_mont(p4, res, p2); /* f*p */

  ecp_nistz256_sqr_mont(res, p4);
  ecp_nistz256_sqr_mont(res, res);
  ecp_nistz256_sqr_mont(res, res);
  ecp_nistz256_sqr_mont(res, res);
  ecp_nistz256_mul_mont(p8, res, p4); /* ff*p */

  ecp_nistz256_sqr_mont(res, p8);
  for (i = 0; i < 7; i++) {
    ecp_nistz256_sqr_mont(res, res);
  }
  ecp_nistz256_mul_mont(p16, res, p8); /* ffff*p */

  ecp_nistz256_sqr_mont(res, p16);
  for (i = 0; i < 15; i++) {
    ecp_nistz256_sqr_mont(res, res);
  }
  ecp_nistz256_mul_mont(p32, res, p16); /* ffffffff*p */

  ecp_nistz256_sqr_mont(res, p32);
  for (i = 0; i < 31; i++) {
    ecp_nistz256_sqr_mont(res, res);
  }
  ecp_nistz256_mul_mont(res, res, in);

  for (i = 0; i < 32 * 4; i++) {
    ecp_nistz256_sqr_mont(res, res);
  }
  ecp_nistz256_mul_mont(res, res, p32);

  for (i = 0; i < 32; i++) {
    ecp_nistz256_sqr_mont(res, res);
  }
  ecp_nistz256_mul_mont(res, res, p32);

  for (i = 0; i < 16; i++) {
    ecp_nistz256_sqr_mont(res, res);
  }
  ecp_nistz256_mul_mont(res, res, p16);

  for (i = 0; i < 8; i++) {
    ecp_nistz256_sqr_mont(res, res);
  }
  ecp_nistz256_mul_mont(res, res, p8);

  ecp_nistz256_sqr_mont(res, res);
  ecp_nistz256_sqr_mont(res, res);
  ecp_nistz256_sqr_mont(res, res);
  ecp_nistz256_sqr_mont(res, res);
  ecp_nistz256_mul_mont(res, res, p4);

  ecp_nistz256_sqr_mont(res, res);
  ecp_nistz256_sqr_mont(res, res);
  ecp_nistz256_mul_mont(res, res, p2);

  ecp_nistz256_sqr_mont(res, res);
  ecp_nistz256_sqr_mont(res, res);
  ecp_nistz256_mul_mont(res, res, in);

  memcpy(r, res, sizeof(res));
}

/* ecp_nistz256_bignum_to_field_elem copies the contents of |in| to |out| and
 * returns one if it fits. Otherwise it returns zero. */
static int ecp_nistz256_bignum_to_field_elem(BN_ULONG out[P256_LIMBS],
                                             const BIGNUM *in) {
  if (in->top > P256_LIMBS) {
    return 0;
  }

  memset(out, 0, sizeof(BN_ULONG) * P256_LIMBS);
  memcpy(out, in->d, sizeof(BN_ULONG) * in->top);
  return 1;
}

/* r = sum(scalar[i]*point[i]) */
static void ecp_nistz256_windowed_mul(const EC_GROUP *group, P256_POINT *r,
                                      const BIGNUM **scalar,
                                      const EC_POINT **point, int num,
                                      BN_CTX *ctx) {
  int i, j;
  unsigned int index;
  unsigned char(*p_str)[33] = NULL;
  const unsigned int window_size = 5;
  const unsigned int mask = (1 << (window_size + 1)) - 1;
  unsigned int wvalue;
  BN_ULONG tmp[P256_LIMBS];
  ALIGN32 P256_POINT h;
  const BIGNUM **scalars = NULL;
  P256_POINT(*table)[16] = NULL;
  void *table_storage = NULL;

  if ((table_storage = OPENSSL_malloc(num * 16 * sizeof(P256_POINT) + 64)) ==
          NULL ||
      (p_str = OPENSSL_malloc(num * 33 * sizeof(unsigned char))) == NULL ||
      (scalars = OPENSSL_malloc(num * sizeof(BIGNUM *))) == NULL) {
    OPENSSL_PUT_ERROR(EC, ERR_R_MALLOC_FAILURE);
    goto err;
  } else {
    table = (void *)ALIGNPTR(table_storage, 64);
  }

  for (i = 0; i < num; i++) {
    P256_POINT *row = table[i];

    if (BN_num_bits(scalar[i]) > 256 || BN_is_negative(scalar[i])) {
      BIGNUM *mod;

      if ((mod = BN_CTX_get(ctx)) == NULL) {
        goto err;
      }

      if (!BN_nnmod(mod, scalar[i], &group->order, ctx)) {
        OPENSSL_PUT_ERROR(EC, ERR_R_BN_LIB);
        goto err;
      }
      scalars[i] = mod;
    } else {
      scalars[i] = scalar[i];
    }

    for (j = 0; j < scalars[i]->top * BN_BYTES; j += BN_BYTES) {
      BN_ULONG d = scalars[i]->d[j / BN_BYTES];

      p_str[i][j + 0] = d & 0xff;
      p_str[i][j + 1] = (d >> 8) & 0xff;
      p_str[i][j + 2] = (d >> 16) & 0xff;
      p_str[i][j + 3] = (d >>= 24) & 0xff;
      if (BN_BYTES == 8) {
        d >>= 8;
        p_str[i][j + 4] = d & 0xff;
        p_str[i][j + 5] = (d >> 8) & 0xff;
        p_str[i][j + 6] = (d >> 16) & 0xff;
        p_str[i][j + 7] = (d >> 24) & 0xff;
      }
    }

    for (; j < 33; j++) {
      p_str[i][j] = 0;
    }

    /* table[0] is implicitly (0,0,0) (the point at infinity), therefore it is
     * not stored. All other values are actually stored with an offset of -1 in
     * table. */

    if (!ecp_nistz256_bignum_to_field_elem(row[1 - 1].X, &point[i]->X) ||
        !ecp_nistz256_bignum_to_field_elem(row[1 - 1].Y, &point[i]->Y) ||
        !ecp_nistz256_bignum_to_field_elem(row[1 - 1].Z, &point[i]->Z)) {
      OPENSSL_PUT_ERROR(EC, EC_R_COORDINATES_OUT_OF_RANGE);
      goto err;
    }

    ecp_nistz256_point_double(&row[2 - 1], &row[1 - 1]);
    ecp_nistz256_point_add(&row[3 - 1], &row[2 - 1], &row[1 - 1]);
    ecp_nistz256_point_double(&row[4 - 1], &row[2 - 1]);
    ecp_nistz256_point_double(&row[6 - 1], &row[3 - 1]);
    ecp_nistz256_point_double(&row[8 - 1], &row[4 - 1]);
    ecp_nistz256_point_double(&row[12 - 1], &row[6 - 1]);
    ecp_nistz256_point_add(&row[5 - 1], &row[4 - 1], &row[1 - 1]);
    ecp_nistz256_point_add(&row[7 - 1], &row[6 - 1], &row[1 - 1]);
    ecp_nistz256_point_add(&row[9 - 1], &row[8 - 1], &row[1 - 1]);
    ecp_nistz256_point_add(&row[13 - 1], &row[12 - 1], &row[1 - 1]);
    ecp_nistz256_point_double(&row[14 - 1], &row[7 - 1]);
    ecp_nistz256_point_double(&row[10 - 1], &row[5 - 1]);
    ecp_nistz256_point_add(&row[15 - 1], &row[14 - 1], &row[1 - 1]);
    ecp_nistz256_point_add(&row[11 - 1], &row[10 - 1], &row[1 - 1]);
    ecp_nistz256_point_add(&row[16 - 1], &row[15 - 1], &row[1 - 1]);
  }

  index = 255;

  wvalue = p_str[0][(index - 1) / 8];
  wvalue = (wvalue >> ((index - 1) % 8)) & mask;

  ecp_nistz256_select_w5(r, table[0], booth_recode_w5(wvalue) >> 1);

  while (index >= 5) {
    for (i = (index == 255 ? 1 : 0); i < num; i++) {
      unsigned int off = (index - 1) / 8;

      wvalue = p_str[i][off] | p_str[i][off + 1] << 8;
      wvalue = (wvalue >> ((index - 1) % 8)) & mask;

      wvalue = booth_recode_w5(wvalue);

      ecp_nistz256_select_w5(&h, table[i], wvalue >> 1);

      ecp_nistz256_neg(tmp, h.Y);
      copy_conditional(h.Y, tmp, (wvalue & 1));

      ecp_nistz256_point_add(r, r, &h);
    }

    index -= window_size;

    ecp_nistz256_point_double(r, r);
    ecp_nistz256_point_double(r, r);
    ecp_nistz256_point_double(r, r);
    ecp_nistz256_point_double(r, r);
    ecp_nistz256_point_double(r, r);
  }

  /* Final window */
  for (i = 0; i < num; i++) {
    wvalue = p_str[i][0];
    wvalue = (wvalue << 1) & mask;

    wvalue = booth_recode_w5(wvalue);

    ecp_nistz256_select_w5(&h, table[i], wvalue >> 1);

    ecp_nistz256_neg(tmp, h.Y);
    copy_conditional(h.Y, tmp, wvalue & 1);

    ecp_nistz256_point_add(r, r, &h);
  }

err:
  OPENSSL_free(table_storage);
  OPENSSL_free(p_str);
  OPENSSL_free(scalars);
}

/* Coordinates of G, for which we have precomputed tables */
const static BN_ULONG def_xG[P256_LIMBS] = {
    TOBN(0x79e730d4, 0x18a9143c), TOBN(0x75ba95fc, 0x5fedb601),
    TOBN(0x79fb732b, 0x77622510), TOBN(0x18905f76, 0xa53755c6),
};

const static BN_ULONG def_yG[P256_LIMBS] = {
    TOBN(0xddf25357, 0xce95560a), TOBN(0x8b4ab8e4, 0xba19e45c),
    TOBN(0xd2e88688, 0xdd21f325), TOBN(0x8571ff18, 0x25885d85)
};

/* ecp_nistz256_is_affine_G returns one if |generator| is the standard, P-256
 * generator. */
static int ecp_nistz256_is_affine_G(const EC_POINT *generator) {
  return (generator->X.top == P256_LIMBS) && (generator->Y.top == P256_LIMBS) &&
         (generator->Z.top == (P256_LIMBS - P256_LIMBS / 8)) &&
         is_equal(generator->X.d, def_xG) && is_equal(generator->Y.d, def_yG) &&
         is_one(generator->Z.d);
}

/* r = scalar*G + sum(scalars[i]*points[i]) */
static int ecp_nistz256_points_mul(
    const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar, size_t num,
    const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *ctx) {
  int i = 0, ret = 0, no_precomp_for_generator = 0, p_is_infinity = 0;
  size_t j;
  unsigned char p_str[33] = {0};
  const PRECOMP256_ROW *preComputedTable = NULL;
  const EC_POINT *generator = NULL;
  unsigned int index = 0;
  const unsigned int window_size = 7;
  const unsigned int mask = (1 << (window_size + 1)) - 1;
  unsigned int wvalue;
  ALIGN32 union {
    P256_POINT p;
    P256_POINT_AFFINE a;
  } t, p;
  BIGNUM *tmp_scalar;

  if (group->meth != r->meth) {
    OPENSSL_PUT_ERROR(EC, EC_R_INCOMPATIBLE_OBJECTS);
    return 0;
  }
  if (scalar == NULL && num == 0) {
    return EC_POINT_set_to_infinity(group, r);
  }

  for (j = 0; j < num; j++) {
    if (group->meth != points[j]->meth) {
      OPENSSL_PUT_ERROR(EC, EC_R_INCOMPATIBLE_OBJECTS);
      return 0;
    }
  }

  /* Need 256 bits for space for all coordinates. */
  bn_wexpand(&r->X, P256_LIMBS);
  bn_wexpand(&r->Y, P256_LIMBS);
  bn_wexpand(&r->Z, P256_LIMBS);
  r->X.top = P256_LIMBS;
  r->Y.top = P256_LIMBS;
  r->Z.top = P256_LIMBS;

  if (scalar) {
    generator = EC_GROUP_get0_generator(group);
    if (generator == NULL) {
      OPENSSL_PUT_ERROR(EC, EC_R_UNDEFINED_GENERATOR);
      goto err;
    }

    if (ecp_nistz256_is_affine_G(generator)) {
      /* If there is no precomputed data, but the generator is the default, a
       * hardcoded table of precomputed data is used. This is because
       * applications, such as Apache, do not use EC_KEY_precompute_mult. */
      preComputedTable = (const PRECOMP256_ROW *)ecp_nistz256_precomputed;
    }

    if (preComputedTable) {
      if (BN_num_bits(scalar) > 256 || BN_is_negative(scalar)) {
        if ((tmp_scalar = BN_CTX_get(ctx)) == NULL) {
          goto err;
        }

        if (!BN_nnmod(tmp_scalar, scalar, &group->order, ctx)) {
          OPENSSL_PUT_ERROR(EC, ERR_R_BN_LIB);
          goto err;
        }
        scalar = tmp_scalar;
      }

      for (i = 0; i < scalar->top * BN_BYTES; i += BN_BYTES) {
        BN_ULONG d = scalar->d[i / BN_BYTES];

        p_str[i + 0] = d & 0xff;
        p_str[i + 1] = (d >> 8) & 0xff;
        p_str[i + 2] = (d >> 16) & 0xff;
        p_str[i + 3] = (d >>= 24) & 0xff;
        if (BN_BYTES == 8) {
          d >>= 8;
          p_str[i + 4] = d & 0xff;
          p_str[i + 5] = (d >> 8) & 0xff;
          p_str[i + 6] = (d >> 16) & 0xff;
          p_str[i + 7] = (d >> 24) & 0xff;
        }
      }

      for (; i < 33; i++) {
        p_str[i] = 0;
      }

      /* First window */
      wvalue = (p_str[0] << 1) & mask;
      index += window_size;

      wvalue = booth_recode_w7(wvalue);

      ecp_nistz256_select_w7(&p.a, preComputedTable[0], wvalue >> 1);

      ecp_nistz256_neg(p.p.Z, p.p.Y);
      copy_conditional(p.p.Y, p.p.Z, wvalue & 1);

      memcpy(p.p.Z, ONE, sizeof(ONE));

      for (i = 1; i < 37; i++) {
        unsigned int off = (index - 1) / 8;
        wvalue = p_str[off] | p_str[off + 1] << 8;
        wvalue = (wvalue >> ((index - 1) % 8)) & mask;
        index += window_size;

        wvalue = booth_recode_w7(wvalue);

        ecp_nistz256_select_w7(&t.a, preComputedTable[i], wvalue >> 1);

        ecp_nistz256_neg(t.p.Z, t.a.Y);
        copy_conditional(t.a.Y, t.p.Z, wvalue & 1);

        ecp_nistz256_point_add_affine(&p.p, &p.p, &t.a);
      }
    } else {
      p_is_infinity = 1;
      no_precomp_for_generator = 1;
    }
  } else {
    p_is_infinity = 1;
  }

  if (no_precomp_for_generator) {
    /* Without a precomputed table for the generator, it has to be handled like
     * a normal point. */
    const BIGNUM **new_scalars;
    const EC_POINT **new_points;

    new_scalars = OPENSSL_malloc((num + 1) * sizeof(BIGNUM *));
    if (!new_scalars) {
      OPENSSL_PUT_ERROR(EC, ERR_R_MALLOC_FAILURE);
      return 0;
    }

    new_points = OPENSSL_malloc((num + 1) * sizeof(EC_POINT *));
    if (!new_points) {
      OPENSSL_free(new_scalars);
      OPENSSL_PUT_ERROR(EC, ERR_R_MALLOC_FAILURE);
      return 0;
    }

    memcpy(new_scalars, scalars, num * sizeof(BIGNUM *));
    new_scalars[num] = scalar;
    memcpy(new_points, points, num * sizeof(EC_POINT *));
    new_points[num] = generator;

    scalars = new_scalars;
    points = new_points;
    num++;
  }

  if (num) {
    P256_POINT *out = &t.p;
    if (p_is_infinity) {
      out = &p.p;
    }

    ecp_nistz256_windowed_mul(group, out, scalars, points, num, ctx);

    if (!p_is_infinity) {
      ecp_nistz256_point_add(&p.p, &p.p, out);
    }
  }

  if (no_precomp_for_generator) {
    OPENSSL_free(points);
    OPENSSL_free(scalars);
  }

  memcpy(r->X.d, p.p.X, sizeof(p.p.X));
  memcpy(r->Y.d, p.p.Y, sizeof(p.p.Y));
  memcpy(r->Z.d, p.p.Z, sizeof(p.p.Z));
  bn_correct_top(&r->X);
  bn_correct_top(&r->Y);
  bn_correct_top(&r->Z);

  ret = 1;

err:
  return ret;
}

static int ecp_nistz256_get_affine(const EC_GROUP *group, const EC_POINT *point,
                                   BIGNUM *x, BIGNUM *y, BN_CTX *ctx) {
  BN_ULONG z_inv2[P256_LIMBS];
  BN_ULONG z_inv3[P256_LIMBS];
  BN_ULONG x_aff[P256_LIMBS];
  BN_ULONG y_aff[P256_LIMBS];
  BN_ULONG point_x[P256_LIMBS], point_y[P256_LIMBS], point_z[P256_LIMBS];

  if (EC_POINT_is_at_infinity(group, point)) {
    OPENSSL_PUT_ERROR(EC, EC_R_POINT_AT_INFINITY);
    return 0;
  }

  if (!ecp_nistz256_bignum_to_field_elem(point_x, &point->X) ||
      !ecp_nistz256_bignum_to_field_elem(point_y, &point->Y) ||
      !ecp_nistz256_bignum_to_field_elem(point_z, &point->Z)) {
    OPENSSL_PUT_ERROR(EC, EC_R_COORDINATES_OUT_OF_RANGE);
    return 0;
  }

  ecp_nistz256_mod_inverse(z_inv3, point_z);
  ecp_nistz256_sqr_mont(z_inv2, z_inv3);
  ecp_nistz256_mul_mont(x_aff, z_inv2, point_x);

  if (x != NULL) {
    bn_wexpand(x, P256_LIMBS);
    x->top = P256_LIMBS;
    ecp_nistz256_from_mont(x->d, x_aff);
    bn_correct_top(x);
  }

  if (y != NULL) {
    ecp_nistz256_mul_mont(z_inv3, z_inv3, z_inv2);
    ecp_nistz256_mul_mont(y_aff, z_inv3, point_y);
    bn_wexpand(y, P256_LIMBS);
    y->top = P256_LIMBS;
    ecp_nistz256_from_mont(y->d, y_aff);
    bn_correct_top(y);
  }

  return 1;
}

const EC_METHOD *EC_GFp_nistz256_method(void) {
  static const EC_METHOD ret = {
      ec_GFp_mont_group_init,
      ec_GFp_mont_group_finish,
      ec_GFp_mont_group_clear_finish,
      ec_GFp_mont_group_copy,
      ec_GFp_mont_group_set_curve,
      ecp_nistz256_get_affine,
      ecp_nistz256_points_mul,      /* mul */
      0, /* precompute_mult */
      ec_GFp_mont_field_mul,
      ec_GFp_mont_field_sqr,
      ec_GFp_mont_field_encode,
      ec_GFp_mont_field_decode,
      ec_GFp_mont_field_set_to_one,
  };

  return &ret;
}

#endif /* !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86_64) && \
          !defined(OPENSSL_SMALL) */
