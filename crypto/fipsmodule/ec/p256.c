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

// An implementation of the NIST P-256 elliptic curve point multiplication.
// 256-bit Montgomery form for 64 and 32-bit. Field operations are generated by
// Fiat, which lives in //third_party/fiat.

#include <openssl/base.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include <assert.h>
#include <string.h>

#include "../../internal.h"
#include "../delocate.h"
#include "./internal.h"

#if defined(BORINGSSL_HAS_UINT128)
#include "../../../third_party/fiat/p256_64.h"
#elif defined(OPENSSL_64_BIT)
#include "../../../third_party/fiat/p256_64_msvc.h"
#else
#include "../../../third_party/fiat/p256_32.h"
#endif


// utility functions, handwritten

#if defined(OPENSSL_64_BIT)
#define FIAT_P256_NLIMBS 4
typedef uint64_t fiat_p256_limb_t;
typedef uint64_t fiat_p256_felem[FIAT_P256_NLIMBS];
static const fiat_p256_felem fiat_p256_one = {0x1, 0xffffffff00000000,
                                              0xffffffffffffffff, 0xfffffffe};
#else  // 64BIT; else 32BIT
#define FIAT_P256_NLIMBS 8
typedef uint32_t fiat_p256_limb_t;
typedef uint32_t fiat_p256_felem[FIAT_P256_NLIMBS];
static const fiat_p256_felem fiat_p256_one = {
    0x1, 0x0, 0x0, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0x0};
#endif  // 64BIT


static fiat_p256_limb_t fiat_p256_nz(
    const fiat_p256_limb_t in1[FIAT_P256_NLIMBS]) {
  fiat_p256_limb_t ret;
  fiat_p256_nonzero(&ret, in1);
  return ret;
}

static void fiat_p256_copy(fiat_p256_limb_t out[FIAT_P256_NLIMBS],
                           const fiat_p256_limb_t in1[FIAT_P256_NLIMBS]) {
  for (size_t i = 0; i < FIAT_P256_NLIMBS; i++) {
    out[i] = in1[i];
  }
}

static void fiat_p256_cmovznz(fiat_p256_limb_t out[FIAT_P256_NLIMBS],
                              fiat_p256_limb_t t,
                              const fiat_p256_limb_t z[FIAT_P256_NLIMBS],
                              const fiat_p256_limb_t nz[FIAT_P256_NLIMBS]) {
  fiat_p256_selectznz(out, !!t, z, nz);
}

static void fiat_p256_from_words(fiat_p256_felem out,
                                 const BN_ULONG in[32 / sizeof(BN_ULONG)]) {
  // Typically, |BN_ULONG| and |fiat_p256_limb_t| will be the same type, but on
  // 64-bit platforms without |uint128_t|, they are different. However, on
  // little-endian systems, |uint64_t[4]| and |uint32_t[8]| have the same
  // layout.
  OPENSSL_memcpy(out, in, 32);
}

static void fiat_p256_from_generic(fiat_p256_felem out, const EC_FELEM *in) {
  fiat_p256_from_words(out, in->words);
}

static void fiat_p256_to_generic(EC_FELEM *out, const fiat_p256_felem in) {
  // See |fiat_p256_from_words|.
  OPENSSL_memcpy(out->words, in, 32);
}

// fiat_p256_inv_square calculates |out| = |in|^{-2}
//
// Based on Fermat's Little Theorem:
//   a^p = a (mod p)
//   a^{p-1} = 1 (mod p)
//   a^{p-3} = a^{-2} (mod p)
static void fiat_p256_inv_square(fiat_p256_felem out,
                                 const fiat_p256_felem in) {
  // This implements the addition chain described in
  // https://briansmith.org/ecc-inversion-addition-chains-01#p256_field_inversion
  fiat_p256_felem x2, x3, x6, x12, x15, x30, x32;
  fiat_p256_square(x2, in);   // 2^2 - 2^1
  fiat_p256_mul(x2, x2, in);  // 2^2 - 2^0

  fiat_p256_square(x3, x2);   // 2^3 - 2^1
  fiat_p256_mul(x3, x3, in);  // 2^3 - 2^0

  fiat_p256_square(x6, x3);
  for (int i = 1; i < 3; i++) {
    fiat_p256_square(x6, x6);
  }                           // 2^6 - 2^3
  fiat_p256_mul(x6, x6, x3);  // 2^6 - 2^0

  fiat_p256_square(x12, x6);
  for (int i = 1; i < 6; i++) {
    fiat_p256_square(x12, x12);
  }                             // 2^12 - 2^6
  fiat_p256_mul(x12, x12, x6);  // 2^12 - 2^0

  fiat_p256_square(x15, x12);
  for (int i = 1; i < 3; i++) {
    fiat_p256_square(x15, x15);
  }                             // 2^15 - 2^3
  fiat_p256_mul(x15, x15, x3);  // 2^15 - 2^0

  fiat_p256_square(x30, x15);
  for (int i = 1; i < 15; i++) {
    fiat_p256_square(x30, x30);
  }                              // 2^30 - 2^15
  fiat_p256_mul(x30, x30, x15);  // 2^30 - 2^0

  fiat_p256_square(x32, x30);
  fiat_p256_square(x32, x32);   // 2^32 - 2^2
  fiat_p256_mul(x32, x32, x2);  // 2^32 - 2^0

  fiat_p256_felem ret;
  fiat_p256_square(ret, x32);
  for (int i = 1; i < 31 + 1; i++) {
    fiat_p256_square(ret, ret);
  }                             // 2^64 - 2^32
  fiat_p256_mul(ret, ret, in);  // 2^64 - 2^32 + 2^0

  for (int i = 0; i < 96 + 32; i++) {
    fiat_p256_square(ret, ret);
  }                              // 2^192 - 2^160 + 2^128
  fiat_p256_mul(ret, ret, x32);  // 2^192 - 2^160 + 2^128 + 2^32 - 2^0

  for (int i = 0; i < 32; i++) {
    fiat_p256_square(ret, ret);
  }                              // 2^224 - 2^192 + 2^160 + 2^64 - 2^32
  fiat_p256_mul(ret, ret, x32);  // 2^224 - 2^192 + 2^160 + 2^64 - 2^0

  for (int i = 0; i < 30; i++) {
    fiat_p256_square(ret, ret);
  }                              // 2^254 - 2^222 + 2^190 + 2^94 - 2^30
  fiat_p256_mul(ret, ret, x30);  // 2^254 - 2^222 + 2^190 + 2^94 - 2^0

  fiat_p256_square(ret, ret);
  fiat_p256_square(out, ret);  // 2^256 - 2^224 + 2^192 + 2^96 - 2^2
}

static inline uint64_t shrd_64(uint64_t lo, uint64_t hi, uint64_t n) {
  return (((uint128_t)hi << 64) | (uint128_t)lo) >> (n&63);
}

static void fiat_p256_halve(fiat_p256_felem y, const fiat_p256_felem x) {
  static const fiat_p256_felem minus_half = {
    -UINT64_C(1), -UINT64_C(1) >> 33, -UINT64_C(1) << 63, -UINT64_C(1) << 32 >> 1};
  fiat_p256_felem maybe_minus_half = {0};
  fiat_p256_cmovznz(maybe_minus_half, x[0] & 1, maybe_minus_half, minus_half);

  y[0] = shrd_64(y[0], y[1], 1);
  y[1] = shrd_64(y[1], y[2], 1);
  y[2] = shrd_64(y[2], y[3], 1);
  y[3] = y[3] >> 1;
  fiat_p256_sub(y, y, maybe_minus_half);
}

// Group operations
// ----------------
//
// Building on top of the field operations we have the operations on the
// elliptic curve group itself. Points on the curve are represented in Jacobian
// coordinates.

// Outputs can equal corresponding inputs, i.e., x_out == x_in is allowed.
// while x_out == y_in is not (maybe this works, but it's not tested).

// Addition operation was transcribed to Coq and proven to correspond to naive
// implementations using Affine coordinates, for all suitable fields.  In the
// Coq proofs, issues of constant-time execution and memory layout (aliasing)
// conventions were not considered. Specification of affine coordinates:
// <https://github.com/mit-plv/fiat-crypto/blob/79f8b5f39ed609339f0233098dee1a3c4e6b3080/src/Spec/WeierstrassCurve.v#L28>
// As a sanity check, a proof that these points form a commutative group:
// <https://github.com/mit-plv/fiat-crypto/blob/79f8b5f39ed609339f0233098dee1a3c4e6b3080/src/Curves/Weierstrass/AffineProofs.v#L33>

static void fiat_p256_point_double(fiat_p256_felem out[3],
                                   const fiat_p256_felem in[3]) {
  fiat_p256_felem D, A, tmp; // HMV'04p91
  fiat_p256_add(D, in[1], in[1]); // B
  fiat_p256_square(tmp, in[2]);
  fiat_p256_square(D, D); // C
  fiat_p256_mul(out[2], in[2], in[1]);
  fiat_p256_add(out[2], out[2], out[2]);
  fiat_p256_add(A, in[0], tmp);
  fiat_p256_sub(tmp, in[0], tmp);
  fiat_p256_square(out[1], D);
  fiat_p256_halve(out[1], out[1]); // C^2/2
  fiat_p256_mul(A, A, tmp);
  fiat_p256_add(tmp, A, A); fiat_p256_add(A, A, tmp); // A
  fiat_p256_mul(D, D, in[0]); // D
  fiat_p256_add(tmp, D, D);
  fiat_p256_square(out[0], A);
  fiat_p256_sub(out[0], out[0], tmp);
  fiat_p256_sub(D, D, out[0]);
  fiat_p256_mul(D, D, A);
  fiat_p256_sub(out[1], D, out[1]);
}

// fiat_p256_point_add calculates (x1, y1, z1) + (x2, y2, z2)
//
// This function includes a branch for checking whether the two input points
// are equal, (while not equal to the point at infinity). This case never
// happens during single point multiplication, so there is no timing leak for
// ECDH or ECDSA signing.
static void fiat_p256_point_add_(fiat_p256_felem out[3],
                                const fiat_p256_felem in1[3],
                                const int p2affine,
                                const fiat_p256_felem x2,
                                const fiat_p256_felem y2,
                                const fiat_p256_felem z2) {
  const uint64_t* const in2[3] = {x2, y2, z2};
  fiat_p256_felem x_out, y_out, z_out;  // HMV'04 p89 eqn 3.14
  fiat_p256_limb_t z1nz = fiat_p256_nz(in1[2]);
  fiat_p256_limb_t z2nz = fiat_p256_nz(in2[2]);

  // z1z1 = z1z1 = z1**2
  fiat_p256_felem z1z1;
  fiat_p256_square(z1z1, in1[2]);  // A = Z^2

  // u2 = x2*z1z1
  fiat_p256_felem u2;
  fiat_p256_mul(u2, in2[0], z1z1);  // C = X2*A

  fiat_p256_felem u1, z2z2;
  if (p2affine) {  // Z2 == 1 (special case Z2 = 0 is handled later).
    fiat_p256_copy(u1, in1[0]);
  } else {
    fiat_p256_square(z2z2, in2[2]);
    fiat_p256_mul(u1, in1[0], z2z2);
  }

  // h = u2 - u1
  fiat_p256_felem h;
  fiat_p256_sub(h, u2, u1);  // E = C - X1

  fiat_p256_felem s2;
  fiat_p256_mul(s2, in1[2], z1z1);  // B + Z1*A

  fiat_p256_mul(z_out, h, in1[2]);  // Z3 = E*Z1
  if (!p2affine) {
    fiat_p256_mul(z_out, z_out, in2[2]);
  }

  // s2 = y2 * z1**3
  fiat_p256_mul(s2, s2, in2[1]);  // D = Y2 * B

  fiat_p256_felem s1;
  if (p2affine) {  // Z2 == 1
    fiat_p256_copy(s1, in1[1]);
  } else {
    // s1 = in1[1] * z2**3
    fiat_p256_mul(s1, in2[2], z2z2);
    fiat_p256_mul(s1, s1, in1[1]);
  }

  fiat_p256_limb_t xneq = fiat_p256_nz(h);

  // r = (s2 - s1)
  fiat_p256_felem r;
  fiat_p256_sub(r, s2, s1);  // F = D - Y1

  fiat_p256_limb_t yneq = fiat_p256_nz(r);

  fiat_p256_limb_t is_nontrivial_double = constant_time_is_zero_w(xneq | yneq) &
                                          ~constant_time_is_zero_w(z1nz) &
                                          ~constant_time_is_zero_w(z2nz);
  if (constant_time_declassify_w(is_nontrivial_double)) {
    fiat_p256_point_double(out, in1);
    return;
  }

  fiat_p256_felem Hsqr;
  fiat_p256_square(Hsqr, h);  // G = E^2

  // Rsqr
  fiat_p256_square(x_out, r);  // F^2

  fiat_p256_felem Hcub;
  fiat_p256_mul(Hcub, Hsqr, h);  // H = G*E

  fiat_p256_felem U2;
  fiat_p256_mul(U2, u1, Hsqr);  // I = X1 * G
  fiat_p256_sub(x_out, x_out, Hcub);
  fiat_p256_sub(x_out, x_out, U2);
  fiat_p256_sub(x_out, x_out, U2);

  fiat_p256_sub(h, U2, x_out);

  fiat_p256_felem S2;
  fiat_p256_mul(S2, Hcub, s1);  // Y1 * H
  fiat_p256_mul(h, h, r);       // E * F
  fiat_p256_sub(y_out, h, S2);

  fiat_p256_cmovznz(x_out, z1nz, in2[0], x_out);
  fiat_p256_cmovznz(out[0], z2nz, in1[0], x_out);
  fiat_p256_cmovznz(y_out, z1nz, in2[1], y_out);
  fiat_p256_cmovznz(out[1], z2nz, in1[1], y_out);
  fiat_p256_cmovznz(z_out, z1nz, in2[2], z_out);
  fiat_p256_cmovznz(out[2], z2nz, in1[2], z_out);
}

static void fiat_p256_point_add(fiat_p256_felem out[3],
                                const fiat_p256_felem in1[3],
                                const fiat_p256_felem in2[3]) {
  return fiat_p256_point_add_(out, in1, 0, in2[0], in2[1], in2[2]);
}

static void fiat_p256_point_add_affine(fiat_p256_felem out[3],
                                const fiat_p256_felem in1[3],
                                const fiat_p256_felem in2[3]) {
  return fiat_p256_point_add_(out, in1, 1, in2[0], in2[1], in2[2]);
}

static void fiat_p256_point_add_affine_nz(fiat_p256_felem out[3],
                                const fiat_p256_felem in1[3],
                                const fiat_p256_felem in2[2]) {
  return fiat_p256_point_add_(out, in1, 1, in2[0], in2[1], fiat_p256_one);
}

#include "./p256_table.h"

// fiat_p256_select_point_affine selects the |idx-1|th point from a
// precomputation table and copies it to out. If |idx| is zero, the output is
// the point at infinity.
static void fiat_p256_select_point_affine(
    const fiat_p256_limb_t idx, size_t size,
    const fiat_p256_felem pre_comp[/*size*/][2], fiat_p256_felem out[3]) {
  OPENSSL_memset(out, 0, sizeof(fiat_p256_felem) * 3);
  for (size_t i = 0; i < size; i++) {
    fiat_p256_limb_t mismatch = i ^ (idx - 1);
    fiat_p256_cmovznz(out[0], mismatch, pre_comp[i][0], out[0]);
    fiat_p256_cmovznz(out[1], mismatch, pre_comp[i][1], out[1]);
  }
  fiat_p256_cmovznz(out[2], idx, out[2], fiat_p256_one);
}

// fiat_p256_select_point selects the |idx|th point from a precomputation table
// and copies it to out.
static void fiat_p256_select_point(const fiat_p256_limb_t idx, size_t size,
                                   const fiat_p256_felem pre_comp[/*size*/][3],
                                   fiat_p256_felem out[3]) {
  OPENSSL_memset(out, 0, sizeof(fiat_p256_felem) * 3);
  for (size_t i = 0; i < size; i++) {
    fiat_p256_limb_t mismatch = i ^ idx;
    fiat_p256_cmovznz(out[0], mismatch, pre_comp[i][0], out[0]);
    fiat_p256_cmovznz(out[1], mismatch, pre_comp[i][1], out[1]);
    fiat_p256_cmovznz(out[2], mismatch, pre_comp[i][2], out[2]);
  }
}

// fiat_p256_get_bit returns the |i|th bit in |in|.
static crypto_word_t fiat_p256_get_bit(const EC_SCALAR *in, int i) {
  if (i < 0 || i >= 256) {
    return 0;
  }
#if defined(OPENSSL_64_BIT)
  static_assert(sizeof(BN_ULONG) == 8, "BN_ULONG was not 64-bit");
  return (in->words[i >> 6] >> (i & 63)) & 1;
#else
  static_assert(sizeof(BN_ULONG) == 4, "BN_ULONG was not 32-bit");
  return (in->words[i >> 5] >> (i & 31)) & 1;
#endif
}

// OPENSSL EC_METHOD FUNCTIONS

// Takes the Jacobian coordinates (X, Y, Z) of a point and returns (X', Y') =
// (X/Z^2, Y/Z^3).
static int ec_GFp_nistp256_point_get_affine_coordinates(
    const EC_GROUP *group, const EC_JACOBIAN *point, EC_FELEM *x_out,
    EC_FELEM *y_out) {
  if (constant_time_declassify_int(
          ec_GFp_simple_is_at_infinity(group, point))) {
    OPENSSL_PUT_ERROR(EC, EC_R_POINT_AT_INFINITY);
    return 0;
  }

  fiat_p256_felem z1, z2;
  fiat_p256_from_generic(z1, &point->Z);
  fiat_p256_inv_square(z2, z1);

  if (x_out != NULL) {
    fiat_p256_felem x;
    fiat_p256_from_generic(x, &point->X);
    fiat_p256_mul(x, x, z2);
    fiat_p256_to_generic(x_out, x);
  }

  if (y_out != NULL) {
    fiat_p256_felem y;
    fiat_p256_from_generic(y, &point->Y);
    fiat_p256_square(z2, z2);  // z^-4
    fiat_p256_mul(y, y, z1);   // y * z
    fiat_p256_mul(y, y, z2);   // y * z^-3
    fiat_p256_to_generic(y_out, y);
  }

  return 1;
}

static void ec_GFp_nistp256_add(const EC_GROUP *group, EC_JACOBIAN *r,
                                const EC_JACOBIAN *a, const EC_JACOBIAN *b) {
  fiat_p256_felem p[3], q[3];
  fiat_p256_from_generic(p[0], &a->X);
  fiat_p256_from_generic(p[1], &a->Y);
  fiat_p256_from_generic(p[2], &a->Z);
  fiat_p256_from_generic(q[0], &b->X);
  fiat_p256_from_generic(q[1], &b->Y);
  fiat_p256_from_generic(q[2], &b->Z);
  fiat_p256_point_add(p, p, q);
  fiat_p256_to_generic(&r->X, p[0]);
  fiat_p256_to_generic(&r->Y, p[1]);
  fiat_p256_to_generic(&r->Z, p[2]);
}

static void ec_GFp_nistp256_dbl(const EC_GROUP *group, EC_JACOBIAN *r,
                                const EC_JACOBIAN *a) {
  fiat_p256_felem p[3];
  fiat_p256_from_generic(p[0], &a->X);
  fiat_p256_from_generic(p[1], &a->Y);
  fiat_p256_from_generic(p[2], &a->Z);
  fiat_p256_point_double(p, p);
  fiat_p256_to_generic(&r->X, p[0]);
  fiat_p256_to_generic(&r->Y, p[1]);
  fiat_p256_to_generic(&r->Z, p[2]);
}

static void ec_GFp_nistp256_point_mul(const EC_GROUP *group, EC_JACOBIAN *r,
                                      const EC_JACOBIAN *p,
                                      const EC_SCALAR *scalar) {
  fiat_p256_felem p_pre_comp[17][3];
  OPENSSL_memset(&p_pre_comp, 0, sizeof(p_pre_comp));
  // Precompute multiples.
  fiat_p256_from_generic(p_pre_comp[1][0], &p->X);
  fiat_p256_from_generic(p_pre_comp[1][1], &p->Y);
  fiat_p256_from_generic(p_pre_comp[1][2], &p->Z);
  for (size_t j = 2; j <= 16; ++j) {
    if (j & 1) {
      fiat_p256_point_add(p_pre_comp[j], p_pre_comp[j - 1], p_pre_comp[1]);
    } else {
      fiat_p256_point_double(p_pre_comp[j], p_pre_comp[j / 2]);
    }
  }

  // Set nq to the point at infinity.
  fiat_p256_felem nq[3] = {{0}, {0}, {0}}, ftmp, tmp[3];

  // Loop over |scalar| msb-to-lsb, incorporating |p_pre_comp| every 5th round.
  int skip = 1;  // Save two point operations in the first round.
  for (size_t i = 255; i < 256; i--) {
    // double
    if (!skip) {
      fiat_p256_point_double(nq, nq);
    }

    // do other additions every 5 doublings
    if (i % 5 == 0) {
      crypto_word_t bits = fiat_p256_get_bit(scalar, i + 4) << 5;
      bits |= fiat_p256_get_bit(scalar, i + 3) << 4;
      bits |= fiat_p256_get_bit(scalar, i + 2) << 3;
      bits |= fiat_p256_get_bit(scalar, i + 1) << 2;
      bits |= fiat_p256_get_bit(scalar, i) << 1;
      bits |= fiat_p256_get_bit(scalar, i - 1);
      crypto_word_t sign, digit;
      ec_GFp_nistp_recode_scalar_bits(&sign, &digit, bits);

      // select the point to add or subtract, in constant time.
      fiat_p256_select_point((fiat_p256_limb_t)digit, 17,
                             (const fiat_p256_felem(*)[3])p_pre_comp, tmp);
      fiat_p256_opp(ftmp, tmp[1]);  // (X, -Y, Z) is the negative point.
      fiat_p256_cmovznz(tmp[1], (fiat_p256_limb_t)sign, tmp[1], ftmp);

      if (!skip) {
        fiat_p256_point_add(nq, nq, tmp);
      } else {
        fiat_p256_copy(nq[0], tmp[0]);
        fiat_p256_copy(nq[1], tmp[1]);
        fiat_p256_copy(nq[2], tmp[2]);
        skip = 0;
      }
    }
  }

  fiat_p256_to_generic(&r->X, nq[0]);
  fiat_p256_to_generic(&r->Y, nq[1]);
  fiat_p256_to_generic(&r->Z, nq[2]);
}

static void ec_GFp_nistp256_point_mul_base(const EC_GROUP *group,
                                           EC_JACOBIAN *r,
                                           const EC_SCALAR *scalar) {
  // Set nq to the point at infinity.
  fiat_p256_felem nq[3] = {{0}, {0}, {0}}, tmp[3];

  int skip = 1;  // Save two point operations in the first round.
  for (size_t i = 31; i < 32; i--) {
    if (!skip) {
      fiat_p256_point_double(nq, nq);
    }

    // First, look 32 bits upwards.
    crypto_word_t bits = fiat_p256_get_bit(scalar, i + 224) << 3;
    bits |= fiat_p256_get_bit(scalar, i + 160) << 2;
    bits |= fiat_p256_get_bit(scalar, i + 96) << 1;
    bits |= fiat_p256_get_bit(scalar, i + 32);
    // Select the point to add, in constant time.
    fiat_p256_select_point_affine((fiat_p256_limb_t)bits, 15,
                                  fiat_p256_g_pre_comp[1], tmp);

    if (!skip) {
      fiat_p256_point_add_affine(nq, nq, tmp);
    } else {
      fiat_p256_copy(nq[0], tmp[0]);
      fiat_p256_copy(nq[1], tmp[1]);
      fiat_p256_copy(nq[2], tmp[2]);
      skip = 0;
    }

    // Second, look at the current position.
    bits = fiat_p256_get_bit(scalar, i + 192) << 3;
    bits |= fiat_p256_get_bit(scalar, i + 128) << 2;
    bits |= fiat_p256_get_bit(scalar, i + 64) << 1;
    bits |= fiat_p256_get_bit(scalar, i);
    // Select the point to add, in constant time.
    fiat_p256_select_point_affine((fiat_p256_limb_t)bits, 15,
                                  fiat_p256_g_pre_comp[0], tmp);
    fiat_p256_point_add_affine(nq, nq, tmp);
  }

  fiat_p256_to_generic(&r->X, nq[0]);
  fiat_p256_to_generic(&r->Y, nq[1]);
  fiat_p256_to_generic(&r->Z, nq[2]);
}

static void ec_GFp_nistp256_point_mul_public(const EC_GROUP *group,
                                             EC_JACOBIAN *r,
                                             const EC_SCALAR *g_scalar,
                                             const EC_JACOBIAN *p,
                                             const EC_SCALAR *p_scalar) {
#define P256_WSIZE_PUBLIC 4
  // Precompute multiples of |p|. p_pre_comp[i] is (2*i+1) * |p|.
  fiat_p256_felem p_pre_comp[1 << (P256_WSIZE_PUBLIC - 1)][3];
  fiat_p256_from_generic(p_pre_comp[0][0], &p->X);
  fiat_p256_from_generic(p_pre_comp[0][1], &p->Y);
  fiat_p256_from_generic(p_pre_comp[0][2], &p->Z);
  fiat_p256_felem p2[3];
  fiat_p256_point_double(p2, p_pre_comp[0]);
  for (size_t i = 1; i < OPENSSL_ARRAY_SIZE(p_pre_comp); i++) {
    fiat_p256_point_add(p_pre_comp[i], p_pre_comp[i - 1], p2);
  }

  // Set up the coefficients for |p_scalar|.
  int8_t p_wNAF[257];
  ec_compute_wNAF(group, p_wNAF, p_scalar, 256, P256_WSIZE_PUBLIC);

  // Set |ret| to the point at infinity.
  int skip = 1;  // Save some point operations.
  fiat_p256_felem ret[3] = {{0}, {0}, {0}};
  for (int i = 256; i >= 0; i--) {
    if (!skip) {
      fiat_p256_point_double(ret, ret);
    }

    // For the |g_scalar|, we use the precomputed table without the
    // constant-time lookup.
    if (i <= 31) {
      // First, look 32 bits upwards.
      crypto_word_t bits = fiat_p256_get_bit(g_scalar, i + 224) << 3;
      bits |= fiat_p256_get_bit(g_scalar, i + 160) << 2;
      bits |= fiat_p256_get_bit(g_scalar, i + 96) << 1;
      bits |= fiat_p256_get_bit(g_scalar, i + 32);
      if (bits != 0) {
        size_t index = (size_t)(bits - 1);
        fiat_p256_point_add_affine_nz(ret, ret, fiat_p256_g_pre_comp[1][index]);
        skip = 0;
      }

      // Second, look at the current position.
      bits = fiat_p256_get_bit(g_scalar, i + 192) << 3;
      bits |= fiat_p256_get_bit(g_scalar, i + 128) << 2;
      bits |= fiat_p256_get_bit(g_scalar, i + 64) << 1;
      bits |= fiat_p256_get_bit(g_scalar, i);
      if (bits != 0) {
        size_t index = (size_t)(bits - 1);
        fiat_p256_point_add_affine_nz(ret, ret, fiat_p256_g_pre_comp[0][index]);
        skip = 0;
      }
    }

    int digit = p_wNAF[i];
    if (digit != 0) {
      assert(digit & 1);
      size_t idx = (size_t)(digit < 0 ? (-digit) >> 1 : digit >> 1);
      fiat_p256_felem *y = &p_pre_comp[idx][1], tmp;
      if (digit < 0) {
        fiat_p256_opp(tmp, p_pre_comp[idx][1]);
        y = &tmp;
      }
      if (!skip) {
        fiat_p256_point_add_(ret, ret, 0 /* not mixed */, p_pre_comp[idx][0], *y,
                            p_pre_comp[idx][2]);
      } else {
        fiat_p256_copy(ret[0], p_pre_comp[idx][0]);
        fiat_p256_copy(ret[1], *y);
        fiat_p256_copy(ret[2], p_pre_comp[idx][2]);
        skip = 0;
      }
    }
  }

  fiat_p256_to_generic(&r->X, ret[0]);
  fiat_p256_to_generic(&r->Y, ret[1]);
  fiat_p256_to_generic(&r->Z, ret[2]);
}

static int ec_GFp_nistp256_cmp_x_coordinate(const EC_GROUP *group,
                                            const EC_JACOBIAN *p,
                                            const EC_SCALAR *r) {
  if (ec_GFp_simple_is_at_infinity(group, p)) {
    return 0;
  }

  // We wish to compare X/Z^2 with r. This is equivalent to comparing X with
  // r*Z^2. Note that X and Z are represented in Montgomery form, while r is
  // not.
  fiat_p256_felem Z2_mont;
  fiat_p256_from_generic(Z2_mont, &p->Z);
  fiat_p256_mul(Z2_mont, Z2_mont, Z2_mont);

  fiat_p256_felem r_Z2;
  fiat_p256_from_words(r_Z2, r->words);  // r < order < p, so this is valid.
  fiat_p256_mul(r_Z2, r_Z2, Z2_mont);

  fiat_p256_felem X;
  fiat_p256_from_generic(X, &p->X);
  fiat_p256_from_montgomery(X, X);

  if (OPENSSL_memcmp(&r_Z2, &X, sizeof(r_Z2)) == 0) {
    return 1;
  }

  // During signing the x coefficient is reduced modulo the group order.
  // Therefore there is a small possibility, less than 1/2^128, that group_order
  // < p.x < P. in that case we need not only to compare against |r| but also to
  // compare against r+group_order.
  assert(group->field.N.width == group->order.N.width);
  EC_FELEM tmp;
  BN_ULONG carry =
      bn_add_words(tmp.words, r->words, group->order.N.d, group->field.N.width);
  if (carry == 0 &&
      bn_less_than_words(tmp.words, group->field.N.d, group->field.N.width)) {
    fiat_p256_from_generic(r_Z2, &tmp);
    fiat_p256_mul(r_Z2, r_Z2, Z2_mont);
    if (OPENSSL_memcmp(&r_Z2, &X, sizeof(r_Z2)) == 0) {
      return 1;
    }
  }

  return 0;
}

DEFINE_METHOD_FUNCTION(EC_METHOD, EC_GFp_nistp256_method) {
  out->point_get_affine_coordinates =
      ec_GFp_nistp256_point_get_affine_coordinates;
  out->add = ec_GFp_nistp256_add;
  out->dbl = ec_GFp_nistp256_dbl;
  out->mul = ec_GFp_nistp256_point_mul;
  out->mul_base = ec_GFp_nistp256_point_mul_base;
  out->mul_public = ec_GFp_nistp256_point_mul_public;
  out->felem_mul = ec_GFp_mont_felem_mul;
  out->felem_sqr = ec_GFp_mont_felem_sqr;
  out->felem_to_bytes = ec_GFp_mont_felem_to_bytes;
  out->felem_from_bytes = ec_GFp_mont_felem_from_bytes;
  out->felem_reduce = ec_GFp_mont_felem_reduce;
  // TODO(davidben): This should use the specialized field arithmetic
  // implementation, rather than the generic one.
  out->felem_exp = ec_GFp_mont_felem_exp;
  out->scalar_inv0_montgomery = ec_simple_scalar_inv0_montgomery;
  out->scalar_to_montgomery_inv_vartime =
      ec_simple_scalar_to_montgomery_inv_vartime;
  out->cmp_x_coordinate = ec_GFp_nistp256_cmp_x_coordinate;
}
