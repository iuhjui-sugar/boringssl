/* Copyright (c) 2015, Google Inc.
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

// A 64-bit implementation of the NIST P-256 elliptic curve point
// multiplication. 256-bit Montgomery form, generated using fiat-crypto.
//
// OpenSSL integration was taken from Emilia Kasper's work in ecp_nistp224.c.

#include <openssl/base.h>

#if defined(OPENSSL_64_BIT) && !defined(OPENSSL_WINDOWS)

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include <string.h>

#include "../delocate.h"
#include "../../internal.h"
#include "internal.h"


// "intrinsics"

static uint64_t cmovznz(uint64_t t, uint64_t z, uint64_t nz) {
	t = -(!!t); // all set if nonzero, 0 if 0
	return (t&nz) | ((~t)&z);

	// asm ("testq %1, %1;" "\n"
	// 		"\t" "cmovnzq %3, %0;"
	// 		:"=r"(z)
	// 		:"r"(t), "0"(z), "r"(nz)
	//     );
	// return z;
}

static uint64_t _mulx_u64(uint64_t a, uint64_t b, uint64_t *high) {
  uint128_t x = (uint128_t)a * b;
  *high = (uint64_t) (x >> 64);
  return (uint64_t) x;
}

static uint64_t _addcarryx_u64(uint8_t c, uint64_t a, uint64_t b, uint64_t *low) {
  uint128_t x = (uint128_t)a + b + c;
  *low = (uint64_t) x;
  return (uint64_t) (x>>64);
}

static uint64_t _subborrow_u64(uint8_t c, uint64_t a, uint64_t b, uint64_t *low) {
  uint128_t t = ((uint128_t) b + c);
  uint128_t x = a-t;
  *low = (uint64_t) x;
  return (uint8_t) (x>>127);
}

// fiat-crypto generated code

static void fe_add(uint64_t out[4], const uint64_t in1[4], const uint64_t in2[4]) {
  { const uint64_t x8 = in1[3];
  { const uint64_t x9 = in1[2];
  { const uint64_t x7 = in1[1];
  { const uint64_t x5 = in1[0];
  { const uint64_t x14 = in2[3];
  { const uint64_t x15 = in2[2];
  { const uint64_t x13 = in2[1];
  { const uint64_t x11 = in2[0];
  { uint64_t x17; uint8_t x18 = _addcarryx_u64(0x0, x5, x11, &x17);
  { uint64_t x20; uint8_t x21 = _addcarryx_u64(x18, x7, x13, &x20);
  { uint64_t x23; uint8_t x24 = _addcarryx_u64(x21, x9, x15, &x23);
  { uint64_t x26; uint8_t x27 = _addcarryx_u64(x24, x8, x14, &x26);
  { uint64_t x29; uint8_t x30 = _subborrow_u64(0x0, x17, 0xffffffffffffffffL, &x29);
  { uint64_t x32; uint8_t x33 = _subborrow_u64(x30, x20, 0xffffffff, &x32);
  { uint64_t x35; uint8_t x36 = _subborrow_u64(x33, x23, 0x0, &x35);
  { uint64_t x38; uint8_t x39 = _subborrow_u64(x36, x26, 0xffffffff00000001L, &x38);
  { uint64_t _1; uint8_t x42 = _subborrow_u64(x39, x27, 0x0, &_1);
  { uint64_t x43 = cmovznz(x42, x38, x26);
  { uint64_t x44 = cmovznz(x42, x35, x23);
  { uint64_t x45 = cmovznz(x42, x32, x20);
  { uint64_t x46 = cmovznz(x42, x29, x17);
  out[0] = x46;
  out[1] = x45;
  out[2] = x44;
  out[3] = x43;
  }}}}}}}}}}}}}}}}}}}}}
}

static void fe_opp(uint64_t out[4], const uint64_t in1[4]) {
  { const uint64_t x5 = in1[3];
  { const uint64_t x6 = in1[2];
  { const uint64_t x4 = in1[1];
  { const uint64_t x2 = in1[0];
  { uint64_t x8; uint8_t x9 = _subborrow_u64(0x0, 0x0, x2, &x8);
  { uint64_t x11; uint8_t x12 = _subborrow_u64(x9, 0x0, x4, &x11);
  { uint64_t x14; uint8_t x15 = _subborrow_u64(x12, 0x0, x6, &x14);
  { uint64_t x17; uint8_t x18 = _subborrow_u64(x15, 0x0, x5, &x17);
  { uint64_t x19 = (uint64_t)cmovznz(x18, 0x0, 0xffffffffffffffffL);
  { uint64_t x20 = (x19 & 0xffffffffffffffffL);
  { uint64_t x22; uint8_t x23 = _addcarryx_u64(0x0, x8, x20, &x22);
  { uint64_t x24 = (x19 & 0xffffffff);
  { uint64_t x26; uint8_t x27 = _addcarryx_u64(x23, x11, x24, &x26);
  { uint64_t x29; uint8_t x30 = _addcarryx_u64(x27, x14, 0x0, &x29);
  { uint64_t x31 = (x19 & 0xffffffff00000001L);
  { uint64_t x33; _addcarryx_u64(x30, x17, x31, &x33);
  out[0] = x22;
  out[1] = x26;
  out[2] = x29;
  out[3] = x33;
  }}}}}}}}}}}}}}}}
}

static void fe_mul(uint64_t out[4], const uint64_t in1[4], const uint64_t in2[4]) {
  { const uint64_t x8 = in1[3];
  { const uint64_t x9 = in1[2];
  { const uint64_t x7 = in1[1];
  { const uint64_t x5 = in1[0];
  { const uint64_t x14 = in2[3];
  { const uint64_t x15 = in2[2];
  { const uint64_t x13 = in2[1];
  { const uint64_t x11 = in2[0];
  { uint64_t x18;  uint64_t x17 = _mulx_u64(x5, x11, &x18);
  { uint64_t x21;  uint64_t x20 = _mulx_u64(x5, x13, &x21);
  { uint64_t x24;  uint64_t x23 = _mulx_u64(x5, x15, &x24);
  { uint64_t x27;  uint64_t x26 = _mulx_u64(x5, x14, &x27);
  { uint64_t x29; uint8_t x30 = _addcarryx_u64(0x0, x18, x20, &x29);
  { uint64_t x32; uint8_t x33 = _addcarryx_u64(x30, x21, x23, &x32);
  { uint64_t x35; uint8_t x36 = _addcarryx_u64(x33, x24, x26, &x35);
  { uint64_t x38; _addcarryx_u64(0x0, x36, x27, &x38);
  { uint64_t x42;  uint64_t x41 = _mulx_u64(x17, 0xffffffffffffffffL, &x42);
  { uint64_t x45;  uint64_t x44 = _mulx_u64(x17, 0xffffffff, &x45);
  { uint64_t x48;  uint64_t x47 = _mulx_u64(x17, 0xffffffff00000001L, &x48);
  { uint64_t x50; uint8_t x51 = _addcarryx_u64(0x0, x42, x44, &x50);
  { uint64_t x53; uint8_t x54 = _addcarryx_u64(x51, x45, 0x0, &x53);
  { uint64_t x56; uint8_t x57 = _addcarryx_u64(x54, 0x0, x47, &x56);
  { uint64_t x59; _addcarryx_u64(0x0, x57, x48, &x59);
  { uint64_t _2; uint8_t x63 = _addcarryx_u64(0x0, x17, x41, &_2);
  { uint64_t x65; uint8_t x66 = _addcarryx_u64(x63, x29, x50, &x65);
  { uint64_t x68; uint8_t x69 = _addcarryx_u64(x66, x32, x53, &x68);
  { uint64_t x71; uint8_t x72 = _addcarryx_u64(x69, x35, x56, &x71);
  { uint64_t x74; uint8_t x75 = _addcarryx_u64(x72, x38, x59, &x74);
  { uint64_t x78;  uint64_t x77 = _mulx_u64(x7, x11, &x78);
  { uint64_t x81;  uint64_t x80 = _mulx_u64(x7, x13, &x81);
  { uint64_t x84;  uint64_t x83 = _mulx_u64(x7, x15, &x84);
  { uint64_t x87;  uint64_t x86 = _mulx_u64(x7, x14, &x87);
  { uint64_t x89; uint8_t x90 = _addcarryx_u64(0x0, x78, x80, &x89);
  { uint64_t x92; uint8_t x93 = _addcarryx_u64(x90, x81, x83, &x92);
  { uint64_t x95; uint8_t x96 = _addcarryx_u64(x93, x84, x86, &x95);
  { uint64_t x98; _addcarryx_u64(0x0, x96, x87, &x98);
  { uint64_t x101; uint8_t x102 = _addcarryx_u64(0x0, x65, x77, &x101);
  { uint64_t x104; uint8_t x105 = _addcarryx_u64(x102, x68, x89, &x104);
  { uint64_t x107; uint8_t x108 = _addcarryx_u64(x105, x71, x92, &x107);
  { uint64_t x110; uint8_t x111 = _addcarryx_u64(x108, x74, x95, &x110);
  { uint64_t x113; uint8_t x114 = _addcarryx_u64(x111, x75, x98, &x113);
  { uint64_t x117;  uint64_t x116 = _mulx_u64(x101, 0xffffffffffffffffL, &x117);
  { uint64_t x120;  uint64_t x119 = _mulx_u64(x101, 0xffffffff, &x120);
  { uint64_t x123;  uint64_t x122 = _mulx_u64(x101, 0xffffffff00000001L, &x123);
  { uint64_t x125; uint8_t x126 = _addcarryx_u64(0x0, x117, x119, &x125);
  { uint64_t x128; uint8_t x129 = _addcarryx_u64(x126, x120, 0x0, &x128);
  { uint64_t x131; uint8_t x132 = _addcarryx_u64(x129, 0x0, x122, &x131);
  { uint64_t x134; _addcarryx_u64(0x0, x132, x123, &x134);
  { uint64_t _3; uint8_t x138 = _addcarryx_u64(0x0, x101, x116, &_3);
  { uint64_t x140; uint8_t x141 = _addcarryx_u64(x138, x104, x125, &x140);
  { uint64_t x143; uint8_t x144 = _addcarryx_u64(x141, x107, x128, &x143);
  { uint64_t x146; uint8_t x147 = _addcarryx_u64(x144, x110, x131, &x146);
  { uint64_t x149; uint8_t x150 = _addcarryx_u64(x147, x113, x134, &x149);
  { uint8_t x151 = (x150 + x114);
  { uint64_t x154;  uint64_t x153 = _mulx_u64(x9, x11, &x154);
  { uint64_t x157;  uint64_t x156 = _mulx_u64(x9, x13, &x157);
  { uint64_t x160;  uint64_t x159 = _mulx_u64(x9, x15, &x160);
  { uint64_t x163;  uint64_t x162 = _mulx_u64(x9, x14, &x163);
  { uint64_t x165; uint8_t x166 = _addcarryx_u64(0x0, x154, x156, &x165);
  { uint64_t x168; uint8_t x169 = _addcarryx_u64(x166, x157, x159, &x168);
  { uint64_t x171; uint8_t x172 = _addcarryx_u64(x169, x160, x162, &x171);
  { uint64_t x174; _addcarryx_u64(0x0, x172, x163, &x174);
  { uint64_t x177; uint8_t x178 = _addcarryx_u64(0x0, x140, x153, &x177);
  { uint64_t x180; uint8_t x181 = _addcarryx_u64(x178, x143, x165, &x180);
  { uint64_t x183; uint8_t x184 = _addcarryx_u64(x181, x146, x168, &x183);
  { uint64_t x186; uint8_t x187 = _addcarryx_u64(x184, x149, x171, &x186);
  { uint64_t x189; uint8_t x190 = _addcarryx_u64(x187, x151, x174, &x189);
  { uint64_t x193;  uint64_t x192 = _mulx_u64(x177, 0xffffffffffffffffL, &x193);
  { uint64_t x196;  uint64_t x195 = _mulx_u64(x177, 0xffffffff, &x196);
  { uint64_t x199;  uint64_t x198 = _mulx_u64(x177, 0xffffffff00000001L, &x199);
  { uint64_t x201; uint8_t x202 = _addcarryx_u64(0x0, x193, x195, &x201);
  { uint64_t x204; uint8_t x205 = _addcarryx_u64(x202, x196, 0x0, &x204);
  { uint64_t x207; uint8_t x208 = _addcarryx_u64(x205, 0x0, x198, &x207);
  { uint64_t x210; _addcarryx_u64(0x0, x208, x199, &x210);
  { uint64_t _4; uint8_t x214 = _addcarryx_u64(0x0, x177, x192, &_4);
  { uint64_t x216; uint8_t x217 = _addcarryx_u64(x214, x180, x201, &x216);
  { uint64_t x219; uint8_t x220 = _addcarryx_u64(x217, x183, x204, &x219);
  { uint64_t x222; uint8_t x223 = _addcarryx_u64(x220, x186, x207, &x222);
  { uint64_t x225; uint8_t x226 = _addcarryx_u64(x223, x189, x210, &x225);
  { uint8_t x227 = (x226 + x190);
  { uint64_t x230;  uint64_t x229 = _mulx_u64(x8, x11, &x230);
  { uint64_t x233;  uint64_t x232 = _mulx_u64(x8, x13, &x233);
  { uint64_t x236;  uint64_t x235 = _mulx_u64(x8, x15, &x236);
  { uint64_t x239;  uint64_t x238 = _mulx_u64(x8, x14, &x239);
  { uint64_t x241; uint8_t x242 = _addcarryx_u64(0x0, x230, x232, &x241);
  { uint64_t x244; uint8_t x245 = _addcarryx_u64(x242, x233, x235, &x244);
  { uint64_t x247; uint8_t x248 = _addcarryx_u64(x245, x236, x238, &x247);
  { uint64_t x250; _addcarryx_u64(0x0, x248, x239, &x250);
  { uint64_t x253; uint8_t x254 = _addcarryx_u64(0x0, x216, x229, &x253);
  { uint64_t x256; uint8_t x257 = _addcarryx_u64(x254, x219, x241, &x256);
  { uint64_t x259; uint8_t x260 = _addcarryx_u64(x257, x222, x244, &x259);
  { uint64_t x262; uint8_t x263 = _addcarryx_u64(x260, x225, x247, &x262);
  { uint64_t x265; uint8_t x266 = _addcarryx_u64(x263, x227, x250, &x265);
  { uint64_t x269;  uint64_t x268 = _mulx_u64(x253, 0xffffffffffffffffL, &x269);
  { uint64_t x272;  uint64_t x271 = _mulx_u64(x253, 0xffffffff, &x272);
  { uint64_t x275;  uint64_t x274 = _mulx_u64(x253, 0xffffffff00000001L, &x275);
  { uint64_t x277; uint8_t x278 = _addcarryx_u64(0x0, x269, x271, &x277);
  { uint64_t x280; uint8_t x281 = _addcarryx_u64(x278, x272, 0x0, &x280);
  { uint64_t x283; uint8_t x284 = _addcarryx_u64(x281, 0x0, x274, &x283);
  { uint64_t x286; _addcarryx_u64(0x0, x284, x275, &x286);
  { uint64_t _5; uint8_t x290 = _addcarryx_u64(0x0, x253, x268, &_5);
  { uint64_t x292; uint8_t x293 = _addcarryx_u64(x290, x256, x277, &x292);
  { uint64_t x295; uint8_t x296 = _addcarryx_u64(x293, x259, x280, &x295);
  { uint64_t x298; uint8_t x299 = _addcarryx_u64(x296, x262, x283, &x298);
  { uint64_t x301; uint8_t x302 = _addcarryx_u64(x299, x265, x286, &x301);
  { uint8_t x303 = (x302 + x266);
  { uint64_t x305; uint8_t x306 = _subborrow_u64(0x0, x292, 0xffffffffffffffffL, &x305);
  { uint64_t x308; uint8_t x309 = _subborrow_u64(x306, x295, 0xffffffff, &x308);
  { uint64_t x311; uint8_t x312 = _subborrow_u64(x309, x298, 0x0, &x311);
  { uint64_t x314; uint8_t x315 = _subborrow_u64(x312, x301, 0xffffffff00000001L, &x314);
  { uint64_t _6; uint8_t x318 = _subborrow_u64(x315, x303, 0x0, &_6);
  { uint64_t x319 = cmovznz(x318, x314, x301);
  { uint64_t x320 = cmovznz(x318, x311, x298);
  { uint64_t x321 = cmovznz(x318, x308, x295);
  { uint64_t x322 = cmovznz(x318, x305, x292);
  out[0] = x322;
  out[1] = x321;
  out[2] = x320;
  out[3] = x319;
  }}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
}

static void fe_sub(uint64_t out[4], const uint64_t in1[4], const uint64_t in2[4]) {
  { const uint64_t x8 = in1[3];
  { const uint64_t x9 = in1[2];
  { const uint64_t x7 = in1[1];
  { const uint64_t x5 = in1[0];
  { const uint64_t x14 = in2[3];
  { const uint64_t x15 = in2[2];
  { const uint64_t x13 = in2[1];
  { const uint64_t x11 = in2[0];
  { uint64_t x17; uint8_t x18 = _subborrow_u64(0x0, x5, x11, &x17);
  { uint64_t x20; uint8_t x21 = _subborrow_u64(x18, x7, x13, &x20);
  { uint64_t x23; uint8_t x24 = _subborrow_u64(x21, x9, x15, &x23);
  { uint64_t x26; uint8_t x27 = _subborrow_u64(x24, x8, x14, &x26);
  { uint64_t x28 = (uint64_t)cmovznz(x27, 0x0, 0xffffffffffffffffL);
  { uint64_t x29 = (x28 & 0xffffffffffffffffL);
  { uint64_t x31; uint8_t x32 = _addcarryx_u64(0x0, x17, x29, &x31);
  { uint64_t x33 = (x28 & 0xffffffff);
  { uint64_t x35; uint8_t x36 = _addcarryx_u64(x32, x20, x33, &x35);
  { uint64_t x38; uint8_t x39 = _addcarryx_u64(x36, x23, 0x0, &x38);
  { uint64_t x40 = (x28 & 0xffffffff00000001L);
  { uint64_t x42; _addcarryx_u64(x39, x26, x40, &x42);
  out[0] = x31;
  out[1] = x35;
  out[2] = x38;
  out[3] = x42;
  }}}}}}}}}}}}}}}}}}}}
}

// utility functions, handwritten

#define NLIMBS 4
#define NBYTES 32
typedef uint64_t fe[NLIMBS];
static const fe fe_one = {1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe};
static const uint64_t rrmodp[4] = {3, 0xfffffffbffffffff, 0xfffffffffffffffe, 0x4fffffffd};

static uint64_t fe_nz(const uint64_t in1[NLIMBS]) {
  uint64_t ret = 0;
  for (int i = 0; i < NLIMBS; i++) { ret |= in1[i]; }
  return ret;
}

static void fe_copy(uint64_t out[NLIMBS], const uint64_t in1[NLIMBS]) {
  for (int i = 0; i < NLIMBS; i++) { out[i] = in1[i]; }
}

static void fe_cmovznz(uint64_t out[NLIMBS], uint64_t t, const uint64_t z[NLIMBS], const uint64_t nz[NLIMBS]) {
  for (int i = 0; i < NLIMBS; i++) { out[i] = cmovznz(t, z[i], nz[i]); }
}

static void fe_sqr(uint64_t *out, const uint64_t *in) {
  fe_mul(out, in, in);
}

static void fe_tobytes(uint8_t out[NBYTES], const fe in) {
  // ((aR)*1)/R = a
  fe tmp = {0};
  static const uint64_t _one[NLIMBS] = {1, 0};
  fe_mul(tmp, _one, in);
  for (int i = 0; i<NBYTES; i++) {
    out[i] = (tmp[i/sizeof(tmp[0])] >> (8*(i%sizeof(tmp[0]))))&0xff;
  }
}

static void fe_frombytes(fe out, const uint8_t in[NBYTES]) {
  // (a*(R*R))/R = (aR)
  for (int i = 0; i<NLIMBS; i++) {
    out[i] = 0;
  }
  for (int i = 0; i<NBYTES; i++) {
    out[i/sizeof(out[0])] |= ((uint64_t)in[i]) << (8*(i%sizeof(out[0])));
  }

  fe_mul(out, out, rrmodp);
}

// BN_* compatability wrappers

// To preserve endianness when using BN_bn2bin and BN_bin2bn.
static void flip_endian(uint8_t *out, const uint8_t *in, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    out[i] = in[len - 1 - i];
  }
}

static int BN_bn2bin_little(uint8_t* out, size_t outlen, const BIGNUM* bn) {
  if (BN_is_negative(bn)) {
    OPENSSL_PUT_ERROR(EC, EC_R_BIGNUM_OUT_OF_RANGE);
    return 0;
  }
  // BN_bn2bin eats leading zeroes
  OPENSSL_memset(out, 0, outlen);

  if (BN_num_bytes(bn) > outlen) {
    OPENSSL_PUT_ERROR(EC, EC_R_BIGNUM_OUT_OF_RANGE);
    return 0;
  }

  uint8_t tmp[outlen];
  size_t num_bytes = BN_bn2bin(bn, tmp);
  flip_endian(out, tmp, num_bytes);
  return 1;
}

static int BN_to_fe(fe out, const BIGNUM *bn) {
  uint8_t tmp[NBYTES];
  if (!BN_bn2bin_little(tmp, sizeof(tmp), bn)) { return 0; }
  fe_frombytes(out, tmp);
  return 1;
}

static BIGNUM *fe_to_BN(BIGNUM *out, const fe in) {
  uint8_t tmp1[NBYTES], tmp2[NBYTES];
  fe_tobytes(tmp1, in);
  flip_endian(tmp2, tmp1, NBYTES);
  return BN_bin2bn(tmp2, NBYTES, out);
}

// fe_inv calculates |out| = |in|^{-1}
//
// Based on Fermat's Little Theorem:
//   a^p = a (mod p)
//   a^{p-1} = 1 (mod p)
//   a^{p-2} = a^{-1} (mod p)
static void fe_inv(fe out, const fe in) {
  fe ftmp, ftmp2;
  // each e_I will hold |in|^{2^I - 1}
  fe e2, e4, e8, e16, e32, e64;

  fe_sqr(ftmp, in);  // 2^1
  fe_mul(ftmp, in, ftmp);  // 2^2 - 2^0
  fe_copy(e2, ftmp);
  fe_sqr(ftmp, ftmp);  // 2^3 - 2^1
  fe_sqr(ftmp, ftmp);  // 2^4 - 2^2
  fe_mul(ftmp, ftmp, e2);  // 2^4 - 2^0
  fe_copy(e4, ftmp);
  fe_sqr(ftmp, ftmp);  // 2^5 - 2^1
  fe_sqr(ftmp, ftmp);  // 2^6 - 2^2
  fe_sqr(ftmp, ftmp);  // 2^7 - 2^3
  fe_sqr(ftmp, ftmp);  // 2^8 - 2^4
  fe_mul(ftmp, ftmp, e4);  // 2^8 - 2^0
  fe_copy(e8, ftmp);
  for (size_t i = 0; i < 8; i++) {
    fe_sqr(ftmp, ftmp);
  }  // 2^16 - 2^8
  fe_mul(ftmp, ftmp, e8);  // 2^16 - 2^0
  fe_copy(e16, ftmp);
  for (size_t i = 0; i < 16; i++) {
    fe_sqr(ftmp, ftmp);
  }  // 2^32 - 2^16
  fe_mul(ftmp, ftmp, e16);  // 2^32 - 2^0
  fe_copy(e32, ftmp);
  for (size_t i = 0; i < 32; i++) {
    fe_sqr(ftmp, ftmp);
  }  // 2^64 - 2^32
  fe_copy(e64, ftmp);
  fe_mul(ftmp, ftmp, in);  // 2^64 - 2^32 + 2^0
  for (size_t i = 0; i < 192; i++) {
    fe_sqr(ftmp, ftmp);
  }  // 2^256 - 2^224 + 2^192

  fe_mul(ftmp2, e64, e32);  // 2^64 - 2^0
  for (size_t i = 0; i < 16; i++) {
    fe_sqr(ftmp2, ftmp2);
  }  // 2^80 - 2^16
  fe_mul(ftmp2, ftmp2, e16);  // 2^80 - 2^0
  for (size_t i = 0; i < 8; i++) {
    fe_sqr(ftmp2, ftmp2);
  }  // 2^88 - 2^8
  fe_mul(ftmp2, ftmp2, e8);  // 2^88 - 2^0
  for (size_t i = 0; i < 4; i++) {
    fe_sqr(ftmp2, ftmp2);
  }  // 2^92 - 2^4
  fe_mul(ftmp2, ftmp2, e4);  // 2^92 - 2^0
  fe_sqr(ftmp2, ftmp2);  // 2^93 - 2^1
  fe_sqr(ftmp2, ftmp2);  // 2^94 - 2^2
  fe_mul(ftmp2, ftmp2, e2);  // 2^94 - 2^0
  fe_sqr(ftmp2, ftmp2);  // 2^95 - 2^1
  fe_sqr(ftmp2, ftmp2);  // 2^96 - 2^2
  fe_mul(ftmp2, ftmp2, in);  // 2^96 - 3

  fe_mul(out, ftmp2, ftmp);  // 2^256 - 2^224 + 2^192 + 2^96 - 3
}

// Group operations
// ----------------
//
// Building on top of the field operations we have the operations on the
// elliptic curve group itself. Points on the curve are represented in Jacobian
// coordinates.

// point_double calculates 2*(x_in, y_in, z_in)
//
// The method is taken from:
//   http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
//
// Outputs can equal corresponding inputs, i.e., x_out == x_in is allowed.
// while x_out == y_in is not (maybe this works, but it's not tested).
static void point_double(fe x_out, fe y_out, fe z_out,
                         const fe x_in, const fe y_in, const fe z_in) {
  fe delta, gamma, beta, ftmp, ftmp2, tmptmp, alpha, fourbeta;
  // delta = z^2
  fe_sqr(delta, z_in);
  // gamma = y^2
  fe_sqr(gamma, y_in);
  // beta = x*gamma
  fe_mul(beta, x_in, gamma);

  // alpha = 3*(x-delta)*(x+delta)
  fe_sub(ftmp, x_in, delta);
  fe_add(ftmp2, x_in, delta);
  
  fe_add(tmptmp, ftmp2, ftmp2);
  fe_add(ftmp2, ftmp2, tmptmp);
  fe_mul(alpha, ftmp, ftmp2);

  // x' = alpha^2 - 8*beta
  fe_sqr(x_out, alpha);
  fe_add(fourbeta, beta, beta);
  fe_add(fourbeta, fourbeta, fourbeta);
  fe_add(tmptmp, fourbeta, fourbeta);
  fe_sub(x_out, x_out, tmptmp);

  // z' = (y + z)^2 - gamma - delta
  fe_add(delta, gamma, delta);
  fe_add(ftmp, y_in, z_in);
  fe_sqr(z_out, ftmp);
  fe_sub(z_out, z_out, delta);

  // y' = alpha*(4*beta - x') - 8*gamma^2
  fe_sub(y_out, fourbeta, x_out);
  fe_add(gamma, gamma, gamma);
  fe_sqr(gamma, gamma);
  fe_mul(y_out, alpha, y_out);
  fe_add(gamma, gamma, gamma);
  fe_sub(y_out, y_out, gamma);
}

// point_add calcuates (x1, y1, z1) + (x2, y2, z2)
//
// The method is taken from:
//   http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl,
// adapted for mixed addition (z2 = 1, or z2 = 0 for the point at infinity).
//
// This function includes a branch for checking whether the two input points
// are equal, (while not equal to the point at infinity). This case never
// happens during single point multiplication, so there is no timing leak for
// ECDH or ECDSA signing.
static void point_add(fe x3, fe y3, fe z3, const fe x1,
                      const fe y1, const fe z1, const int mixed,
                      const fe x2, const fe y2, const fe z2) {
  fe x_out, y_out, z_out;
  uint64_t z1nz = fe_nz(z1);
  uint64_t z2nz = fe_nz(z2);

  // ftmp = z1z1 = z1**2
  fe z1z1; fe_sqr(z1z1, z1);

  fe u1, s1, ftmp5;
  if (!mixed) {
    // ftmp2 = z2z2 = z2**2
    fe z2z2; fe_sqr(z2z2, z2);

    // u1 = ftmp3 = x1*z2z2
    fe_mul(u1, x1, z2z2);

    // ftmp5 = (z1 + z2)**2 - (z1z1 + z2z2) = 2z1z2
    fe_add(ftmp5, z1, z2);
    fe_sqr(ftmp5, ftmp5);
    fe_sub(ftmp5, ftmp5, z1z1);
    fe_sub(ftmp5, ftmp5, z2z2);

    // s1 = ftmp2 = y1 * z2**3
    fe_mul(s1, z2, z2z2);
    fe_mul(s1, s1, y1);
  } else {
    // We'll assume z2 = 1 (special case z2 = 0 is handled later).

    // u1 = ftmp3 = x1*z2z2
    fe_copy(u1, x1);
    // ftmp5 = 2z1z2
    fe_add(ftmp5, z1, z1);
    // s1 = ftmp2 = y1 * z2**3
    fe_copy(s1, y1);
  }

  // u2 = x2*z1z1
  fe u2; fe_mul(u2, x2, z1z1);

  // h = ftmp4 = u2 - u1
  fe h; fe_sub(h, u2, u1);

  uint64_t xneq = fe_nz(h);

  // z_out = ftmp5 * h
  fe_mul(z_out, h, ftmp5);

  // ftmp = z1 * z1z1
  fe z1z1z1; fe_mul(z1z1z1, z1, z1z1);

  // s2 = tmp = y2 * z1**3
  fe s2; fe_mul(s2, y2, z1z1z1);

  // r = ftmp5 = (s2 - s1)*2
  fe r;
  fe_sub(r, s2, s1);
  fe_add(r, r, r);

  uint64_t yneq = fe_nz(r);

  if (!xneq && !yneq && z1nz && z2nz) {
    point_double(x_out, y_out, z_out, x1, y1, z1);
    return;
  }

  // I = ftmp = (2h)**2
  fe i;
  fe_add(i, h, h);
  fe_sqr(i, i);

  // J = ftmp2 = h * I
  fe j; fe_mul(j, h, i);

  // V = ftmp4 = U1 * I
  fe v; fe_mul(v, u1, i);

  // x_out = r**2 - J - 2V
  fe_sqr(x_out, r);
  fe_sub(x_out, x_out, j);
  fe_sub(x_out, x_out, v);
  fe_sub(x_out, x_out, v);

  // y_out = r(V-x_out) - 2 * s1 * J
  fe_sub(y_out, v, x_out);
  fe_mul(y_out, y_out, r);
  fe s1j;
  fe_mul(s1j, s1, j);
  fe_sub(y_out, y_out, s1j);
  fe_sub(y_out, y_out, s1j);

  fe_cmovznz(x_out, z1nz, x2, x_out);
  fe_cmovznz(x3, z2nz, x1, x_out);
  fe_cmovznz(y_out, z1nz, y2, y_out);
  fe_cmovznz(y3, z2nz, y1, y_out);
  fe_cmovznz(z_out, z1nz, z2, z_out);
  fe_cmovznz(z3, z2nz, z1, z_out);
}

// Base point pre computation
// --------------------------
//
// Two different sorts of precomputed tables are used in the following code.
// Each contain various points on the curve, where each point is three field
// elements (x, y, z).
//
// For the base point table, z is usually 1 (0 for the point at infinity).
// This table has 2 * 16 elements, starting with the following:
// index | bits    | point
// ------+---------+------------------------------
//     0 | 0 0 0 0 | 0G
//     1 | 0 0 0 1 | 1G
//     2 | 0 0 1 0 | 2^64G
//     3 | 0 0 1 1 | (2^64 + 1)G
//     4 | 0 1 0 0 | 2^128G
//     5 | 0 1 0 1 | (2^128 + 1)G
//     6 | 0 1 1 0 | (2^128 + 2^64)G
//     7 | 0 1 1 1 | (2^128 + 2^64 + 1)G
//     8 | 1 0 0 0 | 2^192G
//     9 | 1 0 0 1 | (2^192 + 1)G
//    10 | 1 0 1 0 | (2^192 + 2^64)G
//    11 | 1 0 1 1 | (2^192 + 2^64 + 1)G
//    12 | 1 1 0 0 | (2^192 + 2^128)G
//    13 | 1 1 0 1 | (2^192 + 2^128 + 1)G
//    14 | 1 1 1 0 | (2^192 + 2^128 + 2^64)G
//    15 | 1 1 1 1 | (2^192 + 2^128 + 2^64 + 1)G
// followed by a copy of this with each element multiplied by 2^32.
//
// The reason for this is so that we can clock bits into four different
// locations when doing simple scalar multiplies against the base point,
// and then another four locations using the second 16 elements.
//
// Tables for other points have table[i] = iG for i in 0 .. 16.

// g_pre_comp is the table of precomputed base points
static const fe g_pre_comp[2][16][3] = {
    {{{0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0}},
     {{0x79e730d418a9143c, 0x75ba95fc5fedb601, 0x79fb732b77622510,
       0x18905f76a53755c6},
      {0xddf25357ce95560a, 0x8b4ab8e4ba19e45c, 0xd2e88688dd21f325,
       0x8571ff1825885d85},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0x4f922fc516a0d2bb, 0xd5cc16c1a623499, 0x9241cf3a57c62c8b,
       0x2f5e6961fd1b667f},
      {0x5c15c70bf5a01797, 0x3d20b44d60956192, 0x4911b37071fdb52,
       0xf648f9168d6f0f7b},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0x9e566847e137bbbc, 0xe434469e8a6a0bec, 0xb1c4276179d73463,
       0x5abe0285133d0015},
      {0x92aa837cc04c7dab, 0x573d9f4c43260c07, 0xc93156278e6cc37,
       0x94bb725b6b6f7383},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0x62a8c244bfe20925, 0x91c19ac38fdce867, 0x5a96a5d5dd387063,
       0x61d587d421d324f6},
      {0xe87673a2a37173ea, 0x2384800853778b65, 0x10f8441e05bab43e,
       0xfa11fe124621efbe},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0x1c891f2b2cb19ffd, 0x1ba8d5bb1923c23, 0xb6d03d678ac5ca8e,
       0x586eb04c1f13bedc},
      {0xc35c6e527e8ed09, 0x1e81a33c1819ede2, 0x278fd6c056c652fa,
       0x19d5ac0870864f11},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0x62577734d2b533d5, 0x673b8af6a1bdddc0, 0x577e7c9aa79ec293,
       0xbb6de651c3b266b1},
      {0xe7e9303ab65259b3, 0xd6a0afd3d03a7480, 0xc5ac83d19b3cfc27,
       0x60b4619a5d18b99b},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0xbd6a38e11ae5aa1c, 0xb8b7652b49e73658, 0xb130014ee5f87ed,
       0x9d0f27b2aeebffcd},
      {0xca9246317a730a55, 0x9c955b2fddbbc83a, 0x7c1dfe0ac019a71,
       0x244a566d356ec48d},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0x56f8410ef4f8b16a, 0x97241afec47b266a, 0xa406b8e6d9c87c1,
       0x803f3e02cd42ab1b},
      {0x7f0309a804dbec69, 0xa83b85f73bbad05f, 0xc6097273ad8e197f,
       0xc097440e5067adc1},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0x846a56f2c379ab34, 0xa8ee068b841df8d1, 0x20314459176c68ef,
       0xf1af32d5915f1f30},
      {0x99c375315d75bd50, 0x837cffbaf72f67bc, 0x613a41848d7723f,
       0x23d0f130e2d41c8b},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0xed93e225d5be5a2b, 0x6fe799835934f3c6, 0x4314092622626ffc,
       0x50bbb4d97990216a},
      {0x378191c6e57ec63e, 0x65422c40181dcdb2, 0x41a8099b0236e0f6,
       0x2b10011801fe49c3},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0xfc68b5c59b391593, 0xc385f5a2598270fc, 0x7144f3aad19adcbb,
       0xdd55899983fbae0c},
      {0x93b88b8e74b82ff4, 0xd2e03c4071e734c9, 0x9a7a9eaf43c0322a,
       0xe6e4c551149d6041},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0x5fe14bfe80ec21fe, 0xf6ce116ac255be82, 0x98bc5a072f4a5d67,
       0xfad27148db7e63af},
      {0x90c0b6ac29ab05b3, 0x37a9a83c4e251ae6, 0xa7dc875c2aade7d,
       0x77387de39f0e1a84},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0x1e9ecc49a56c0dd7, 0xa5cffcd846086c74, 0x8f7a1408f505aece,
       0xb37b85c0bef0c47e},
      {0x3596b6e4cc0e6a8f, 0xfd6d4bbf6b388f23, 0xaba453fac39cef4e,
       0x9c135ac8f9f628d5},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0xa1c729495c8f8be, 0x2961c4803bf362bf, 0x9e418403df63d4ac,
       0xc109f9cb91ece900},
      {0xc2d095d058945705, 0xb9083d96ddeb85c0, 0x84692b8d7a40449b,
       0x9bc3344f2eee1ee1},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0xd5ae35642913074, 0x55491b2748a542b1, 0x469ca665b310732a,
       0x29591d525f1a4cc1},
      {0xe76f5b6bb84f983f, 0xbe7eef419f5f84e1, 0x1200d49680baa189,
       0x6376551f18ef332c},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}}},
    {{{0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0}, {0x0, 0x0, 0x0, 0x0}},
     {{0x202886024147519a, 0xd0981eac26b372f0, 0xa9d4a7caa785ebc8,
       0xd953c50ddbdf58e9},
      {0x9d6361ccfd590f8f, 0x72e9626b44e6c917, 0x7fd9611022eb64cf,
       0x863ebb7e9eb288f3},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0x4fe7ee31b0e63d34, 0xf4600572a9e54fab, 0xc0493334d5e7b5a4,
       0x8589fb9206d54831},
      {0xaa70f5cc6583553a, 0x879094ae25649e5, 0xcc90450710044652,
       0xebb0696d02541c4f},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0xabbaa0c03b89da99, 0xa6f2d79eb8284022, 0x27847862b81c05e8,
       0x337a4b5905e54d63},
      {0x3c67500d21f7794a, 0x207005b77d6d7f61, 0xa5a378104cfd6e8,
       0xd65e0d5f4c2fbd6},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0xd433e50f6d3549cf, 0x6f33696ffacd665e, 0x695bfdacce11fcb4,
       0x810ee252af7c9860},
      {0x65450fe17159bb2c, 0xf7dfbebe758b357b, 0x2b057e74d69fea72,
       0xd485717a92731745},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0xce1f69bbe83f7669, 0x9f8ae8272877d6b, 0x9548ae543244278d,
       0x207755dee3c2c19c},
      {0x87bd61d96fef1945, 0x18813cefb12d28c3, 0x9fbcd1d672df64aa,
       0x48dc5ee57154b00d},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0xef0f469ef49a3154, 0x3e85a5956e2b2e9a, 0x45aaec1eaa924a9c,
       0xaa12dfc8a09e4719},
      {0x26f272274df69f1d, 0xe0e4c82ca2ff5e73, 0xb9d8ce73b7a9dd44,
       0x6c036e73e48ca901},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0xe1e421e1a47153f0, 0xb86c3b79920418c9, 0x93bdce87705d7672,
       0xf25ae793cab79a77},
      {0x1f3194a36d869d0c, 0x9d55c8824986c264, 0x49fb5ea3096e945e,
       0x39b8e65313db0a3e},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0xe3417bc035d0b34a, 0x440b386b8327c0a7, 0x8fb7262dac0362d1,
       0x2c41114ce0cdf943},
      {0x2ba5cef1ad95a0b1, 0xc09b37a867d54362, 0x26d6cdd201e486c9,
       0x20477abf42ff9297},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0xf121b41bc0a67d2, 0x62d4760a444d248a, 0xe044f1d659b4737,
       0x8fde365250bb4a8},
      {0xaceec3da848bf287, 0xc2a62182d3369d6e, 0x3582dfdc92449482,
       0x2f7e2fd2565d6cd7},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0xa0122b5178a876b, 0x51ff96ff085104b4, 0x50b31ab14f29f76,
       0x84abb28b5f87d4e6},
      {0xd5ed439f8270790a, 0x2d6cb59d85e3f46b, 0x75f55c1b6c1e2212,
       0xe5436f6717655640},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0xc2965ecc9aeb596d, 0x1ea03e7023c92b4, 0x4704b4b62e013961,
       0xca8fd3f905ea367},
      {0x92523a42551b2b61, 0x1eb7a89c390fcd06, 0xe7f1d2be0392a63e,
       0x96dca2644ddb0c33},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0x231c210e15339848, 0xe87a28e870778c8d, 0x9d1de6616956e170,
       0x4ac3c9382bb09c0b},
      {0x19be05516998987d, 0x8b2376c4ae09f4d6, 0x1de0b7651a3f933d,
       0x380d94c7e39705f4},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0x3685954b8c31c31d, 0x68533d005bf21a0c, 0xbd7626e75c79ec9,
       0xca17754742c69d54},
      {0xcc6edafff6d2dbb2, 0xfd0d8cbd174a9d18, 0x875e8793aa4578e8,
       0xa976a7139cab2ce6},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0xce37ab11b43ea1db, 0xa7ff1a95259d292, 0x851b02218f84f186,
       0xa7222beadefaad13},
      {0xa2ac78ec2b0a9144, 0x5a024051f2fa59c5, 0x91d1eca56147ce38,
       0xbe94d523bc2ac690},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}},
     {{0x2d8daefd79ec1a0f, 0x3bbcd6fdceb39c97, 0xf5575ffc58f61a95,
       0xdbd986c4adf7b420},
      {0x81aa881415f39eb7, 0x6ee2fcf5b98d976c, 0x5465475dcf2f717d,
       0x8e24d3c46860bbd0},
      {0x1, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffe}}}};


// select_point selects the |idx|th point from a precomputation table and
// copies it to out.
static void select_point(const uint64_t idx, size_t size,
                         const fe pre_comp[/*size*/][3],
                         fe out[3]) {
  uint64_t* outlimbs = &out[0][0];
  for (size_t j = 0; j < NLIMBS * 3; j++) { outlimbs[j] = 0; }
  for (size_t i = 0; i < size; i++) {
    const uint64_t *inlimbs = (const uint64_t *)&pre_comp[i][0][0];
    uint64_t mask = i ^ idx;
    mask |= mask >> 4;
    mask |= mask >> 2;
    mask |= mask >> 1;
    mask &= 1;
    mask--;
    for (size_t j = 0; j < NLIMBS * 3; j++) {
      outlimbs[j] |= inlimbs[j] & mask;
    }
  }
}

// get_bit returns the |i|th bit in |in|
static char get_bit(const uint8_t *in, int i) {
  if (i < 0 || i >= 256) {
    return 0;
  }
  return (in[i >> 3] >> (i & 7)) & 1;
}

// Interleaved point multiplication using precomputed point multiples: The
// small point multiples 0*P, 1*P, ..., 17*P are in p_pre_comp, the scalar
// in p_scalar, if non-NULL. If g_scalar is non-NULL, we also add this multiple
// of the generator, using certain (large) precomputed multiples in g_pre_comp.
// Output point (X, Y, Z) is stored in x_out, y_out, z_out.
static void batch_mul(fe x_out, fe y_out, fe z_out,
                      const uint8_t *p_scalar, const uint8_t *g_scalar,
                      const fe p_pre_comp[17][3]) {
  fe nq[3] = {{0},{0},{0}}, ftmp, tmp[3];
  uint64_t bits;
  uint8_t sign, digit;

  // Loop over both scalars msb-to-lsb, interleaving additions of multiples
  // of the generator (two in each of the last 32 rounds) and additions of p
  // (every 5th round).

  int skip = 1;  // save two point operations in the first round
  size_t i = p_scalar != NULL ? 255 : 31;
  for (;;) {
    // double
    if (!skip) {
      point_double(nq[0], nq[1], nq[2], nq[0], nq[1], nq[2]);
    }

    // add multiples of the generator
    if (g_scalar != NULL && i <= 31) {
      // first, look 32 bits upwards
      bits = get_bit(g_scalar, i + 224) << 3;
      bits |= get_bit(g_scalar, i + 160) << 2;
      bits |= get_bit(g_scalar, i + 96) << 1;
      bits |= get_bit(g_scalar, i + 32);
      // select the point to add, in constant time
      select_point(bits, 16, g_pre_comp[1], tmp);

      if (!skip) {
        point_add(nq[0], nq[1], nq[2], nq[0], nq[1], nq[2], 1 /* mixed */,
                  tmp[0], tmp[1], tmp[2]);
      } else {
        fe_copy(nq[0], tmp[0]);
        fe_copy(nq[1], tmp[1]);
        fe_copy(nq[2], tmp[2]);
        skip = 0;
      }

      // second, look at the current position
      bits = get_bit(g_scalar, i + 192) << 3;
      bits |= get_bit(g_scalar, i + 128) << 2;
      bits |= get_bit(g_scalar, i + 64) << 1;
      bits |= get_bit(g_scalar, i);
      // select the point to add, in constant time
      select_point(bits, 16, g_pre_comp[0], tmp);
      point_add(nq[0], nq[1], nq[2], nq[0], nq[1], nq[2], 1 /* mixed */, tmp[0],
                tmp[1], tmp[2]);
    }

    // do other additions every 5 doublings
    if (p_scalar != NULL && i % 5 == 0) {
      bits = get_bit(p_scalar, i + 4) << 5;
      bits |= get_bit(p_scalar, i + 3) << 4;
      bits |= get_bit(p_scalar, i + 2) << 3;
      bits |= get_bit(p_scalar, i + 1) << 2;
      bits |= get_bit(p_scalar, i) << 1;
      bits |= get_bit(p_scalar, i - 1);
      ec_GFp_nistp_recode_scalar_bits(&sign, &digit, bits);

      // select the point to add or subtract, in constant time.
      select_point(digit, 17, p_pre_comp, tmp);
      fe_opp(ftmp, tmp[1]);  // (X, -Y, Z) is the negative point.
      fe_cmovznz(tmp[1], sign, tmp[1], ftmp);

      if (!skip) {
        point_add(nq[0], nq[1], nq[2], nq[0], nq[1], nq[2], 0 /* mixed */,
                  tmp[0], tmp[1], tmp[2]);
      } else {
        fe_copy(nq[0], tmp[0]);
        fe_copy(nq[1], tmp[1]);
        fe_copy(nq[2], tmp[2]);
        skip = 0;
      }
    }

    if (i == 0) {
      break;
    }
    --i;
  }
  fe_copy(x_out, nq[0]);
  fe_copy(y_out, nq[1]);
  fe_copy(z_out, nq[2]);
}

// OPENSSL EC_METHOD FUNCTIONS

// Takes the Jacobian coordinates (X, Y, Z) of a point and returns (X', Y') =
// (X/Z^2, Y/Z^3).
static int ec_GFp_nistp256_point_get_affine_coordinates(const EC_GROUP *group,
                                                        const EC_POINT *point,
                                                        BIGNUM *x_out, BIGNUM *y_out,
                                                        BN_CTX *ctx) {
  fe x, y, z1, z2;

  if (EC_POINT_is_at_infinity(group, point)) {
    OPENSSL_PUT_ERROR(EC, EC_R_POINT_AT_INFINITY);
    return 0;
  }
  if (!BN_to_fe(x, &point->X) ||
      !BN_to_fe(y, &point->Y) ||
      !BN_to_fe(z1, &point->Z)) {
    return 0;
  }

  fe_inv(z2, z1);
  fe_sqr(z1, z2);

  if (x_out != NULL) {
    fe_mul(x, x, z1);
    if (!fe_to_BN(x_out, x)) {
      OPENSSL_PUT_ERROR(EC, ERR_R_BN_LIB);
      return 0;
    }
  }

  if (y_out != NULL) {
    fe_mul(z1, z1, z2);
    fe_mul(y, y, z1);
    if (!fe_to_BN(y_out, y)) {
      OPENSSL_PUT_ERROR(EC, ERR_R_BN_LIB);
      return 0;
    }
  }

  return 1;
}

static int ec_GFp_nistp256_points_mul(const EC_GROUP *group, EC_POINT *r,
                                      const BIGNUM *g_scalar, const EC_POINT *p,
                                      const BIGNUM *p_scalar, BN_CTX *ctx) {
  int ret = 0;
  BN_CTX *new_ctx = NULL;
  BIGNUM *x, *y, *z, *tmp_scalar;
  uint8_t g_secret[NBYTES], p_secret[NBYTES], tmp[NBYTES];
  fe p_pre_comp[17][3];
  fe x_out, y_out, z_out;

  if (ctx == NULL) {
    ctx = new_ctx = BN_CTX_new();
    if (ctx == NULL) {
      return 0;
    }
  }

  BN_CTX_start(ctx);
  if ((x = BN_CTX_get(ctx)) == NULL ||
      (y = BN_CTX_get(ctx)) == NULL ||
      (z = BN_CTX_get(ctx)) == NULL ||
      (tmp_scalar = BN_CTX_get(ctx)) == NULL) {
    goto err;
  }

  if (p != NULL && p_scalar != NULL) {
    // We treat NULL scalars as 0, and NULL points as points at infinity, i.e.,
    // they contribute nothing to the linear combination.
    OPENSSL_memset(&p_secret, 0, sizeof(p_secret));
    OPENSSL_memset(&p_pre_comp, 0, sizeof(p_pre_comp));
    size_t num_bytes;
    // Reduce g_scalar to 0 <= g_scalar < 2^256.
    if (BN_num_bits(p_scalar) > 256 || BN_is_negative(p_scalar)) {
      // This is an unusual input, and we don't guarantee constant-timeness.
      if (!BN_nnmod(tmp_scalar, p_scalar, &group->order, ctx)) {
        OPENSSL_PUT_ERROR(EC, ERR_R_BN_LIB);
        goto err;
      }
      num_bytes = BN_bn2bin(tmp_scalar, tmp);
    } else {
      num_bytes = BN_bn2bin(p_scalar, tmp);
    }
    flip_endian(p_secret, tmp, num_bytes);
    // Precompute multiples.
    if (!BN_to_fe(p_pre_comp[1][0], &p->X) ||
        !BN_to_fe(p_pre_comp[1][1], &p->Y) ||
        !BN_to_fe(p_pre_comp[1][2], &p->Z)) {
      goto err;
    }
    for (size_t j = 2; j <= 16; ++j) {
      if (j & 1) {
        point_add(p_pre_comp[j][0], p_pre_comp[j][1],
                        p_pre_comp[j][2], p_pre_comp[1][0],
                        p_pre_comp[1][1], p_pre_comp[1][2],
                        0,
                        p_pre_comp[j - 1][0], p_pre_comp[j - 1][1],
                        p_pre_comp[j - 1][2]);
      } else {
        point_double(p_pre_comp[j][0], p_pre_comp[j][1],
                           p_pre_comp[j][2], p_pre_comp[j / 2][0],
                           p_pre_comp[j / 2][1], p_pre_comp[j / 2][2]);
      }
    }
  }

  if (g_scalar != NULL) {
    size_t num_bytes;

    OPENSSL_memset(g_secret, 0, sizeof(g_secret));
    // reduce g_scalar to 0 <= g_scalar < 2^256
    if (BN_num_bits(g_scalar) > 256 || BN_is_negative(g_scalar)) {
      // this is an unusual input, and we don't guarantee
      // constant-timeness.
      if (!BN_nnmod(tmp_scalar, g_scalar, &group->order, ctx)) {
        OPENSSL_PUT_ERROR(EC, ERR_R_BN_LIB);
        goto err;
      }
      num_bytes = BN_bn2bin(tmp_scalar, tmp);
    } else {
      num_bytes = BN_bn2bin(g_scalar, tmp);
    }
    flip_endian(g_secret, tmp, num_bytes);
  }
  batch_mul(x_out, y_out, z_out,
            (p != NULL && p_scalar != NULL) ? p_secret : NULL,
            g_scalar != NULL ? g_secret : NULL,
            p_pre_comp);

  if (!fe_to_BN(x, x_out) ||
      !fe_to_BN(y, y_out) ||
      !fe_to_BN(z, z_out)) {
    OPENSSL_PUT_ERROR(EC, ERR_R_BN_LIB);
    goto err;
  }
  ret = ec_point_set_Jprojective_coordinates_GFp(group, r, x, y, z, ctx);

err:
  BN_CTX_end(ctx);
  BN_CTX_free(new_ctx);
  return ret;
}

DEFINE_METHOD_FUNCTION(EC_METHOD, EC_GFp_nistp256_method) {
  out->group_init = ec_GFp_simple_group_init;
  out->group_finish = ec_GFp_simple_group_finish;
  out->group_set_curve = ec_GFp_simple_group_set_curve;
  out->point_get_affine_coordinates =
      ec_GFp_nistp256_point_get_affine_coordinates;
  out->mul = ec_GFp_nistp256_points_mul;
  out->field_mul = ec_GFp_simple_field_mul;
  out->field_sqr = ec_GFp_simple_field_sqr;
  out->field_encode = NULL;
  out->field_decode = NULL;
};

#endif  // 64_BIT && !WINDOWS
