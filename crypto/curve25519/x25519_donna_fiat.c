/* Copyright 2008, Google Inc.
 * All rights reserved.
 *
 * Code released into the public domain.
 *
 * curve25519-donna: Curve25519 elliptic curve, public key function
 *
 * http://code.google.com/p/curve25519-donna/
 *
 * Adam Langley <agl@imperialviolet.org>
 *
 * Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>
 *
 * More information about curve25519 can be found here
 *   http://cr.yp.to/ecdh.html
 *
 * djb's sample implementation of curve25519 is written in a special assembly
 * language called qhasm and uses the floating point registers.
 *
 * This is, almost, a clean room reimplementation from the curve25519 paper. It
 * uses many of the tricks described therein. Only the crecip function is taken
 * from the sample implementation.
 */

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "internal.h"
#include "../internal.h"


#if defined(BORINGSSL_X25519_FIAT)

typedef uint8_t u8;
typedef uint64_t limb;
typedef limb felem[5];

#undef force_inline
#define force_inline __attribute__((always_inline))

/* Multiply two numbers: output = in2 * in
 *
 * output must be distinct to both inputs. The inputs are reduced coefficient
 * form, the output is not.
 *
 * Assumes that in[i] < 2**55 and likewise for in2.
 * On return, output[i] < 2**52
 */
static inline void force_inline
fmul(felem output, const felem in2, const felem in) {
  uint128_t t[5];
  limb r0,r1,r2,r3,r4,s0,s1,s2,s3,s4,c;

  r0 = in[0];
  r1 = in[1];
  r2 = in[2];
  r3 = in[3];
  r4 = in[4];

  s0 = in2[0];
  s1 = in2[1];
  s2 = in2[2];
  s3 = in2[3];
  s4 = in2[4];

  t[0]  =  ((uint128_t) r0) * s0;
  t[1]  =  ((uint128_t) r0) * s1 + ((uint128_t) r1) * s0;
  t[2]  =  ((uint128_t) r0) * s2 + ((uint128_t) r2) * s0 + ((uint128_t) r1) * s1;
  t[3]  =  ((uint128_t) r0) * s3 + ((uint128_t) r3) * s0 + ((uint128_t) r1) * s2 + ((uint128_t) r2) * s1;
  t[4]  =  ((uint128_t) r0) * s4 + ((uint128_t) r4) * s0 + ((uint128_t) r3) * s1 + ((uint128_t) r1) * s3 + ((uint128_t) r2) * s2;

  r4 *= 19;
  r1 *= 19;
  r2 *= 19;
  r3 *= 19;

  t[0] += ((uint128_t) r4) * s1 + ((uint128_t) r1) * s4 + ((uint128_t) r2) * s3 + ((uint128_t) r3) * s2;
  t[1] += ((uint128_t) r4) * s2 + ((uint128_t) r2) * s4 + ((uint128_t) r3) * s3;
  t[2] += ((uint128_t) r4) * s3 + ((uint128_t) r3) * s4;
  t[3] += ((uint128_t) r4) * s4;

                  r0 = (limb)t[0] & 0x7ffffffffffff; c = (limb)(t[0] >> 51);
  t[1] += c;      r1 = (limb)t[1] & 0x7ffffffffffff; c = (limb)(t[1] >> 51);
  t[2] += c;      r2 = (limb)t[2] & 0x7ffffffffffff; c = (limb)(t[2] >> 51);
  t[3] += c;      r3 = (limb)t[3] & 0x7ffffffffffff; c = (limb)(t[3] >> 51);
  t[4] += c;      r4 = (limb)t[4] & 0x7ffffffffffff; c = (limb)(t[4] >> 51);
  r0 +=   c * 19; c = r0 >> 51; r0 = r0 & 0x7ffffffffffff;
  r1 +=   c;      c = r1 >> 51; r1 = r1 & 0x7ffffffffffff;
  r2 +=   c;

  output[0] = r0;
  output[1] = r1;
  output[2] = r2;
  output[3] = r3;
  output[4] = r4;
}

static inline void force_inline
fsquare_times(felem output, const felem in, limb count) {
  uint128_t t[5];
  limb r0,r1,r2,r3,r4,c;
  limb d0,d1,d2,d4,d419;

  r0 = in[0];
  r1 = in[1];
  r2 = in[2];
  r3 = in[3];
  r4 = in[4];

  do {
    d0 = r0 * 2;
    d1 = r1 * 2;
    d2 = r2 * 2 * 19;
    d419 = r4 * 19;
    d4 = d419 * 2;

    t[0] = ((uint128_t) r0) * r0 + ((uint128_t) d4) * r1 + (((uint128_t) d2) * (r3     ));
    t[1] = ((uint128_t) d0) * r1 + ((uint128_t) d4) * r2 + (((uint128_t) r3) * (r3 * 19));
    t[2] = ((uint128_t) d0) * r2 + ((uint128_t) r1) * r1 + (((uint128_t) d4) * (r3     ));
    t[3] = ((uint128_t) d0) * r3 + ((uint128_t) d1) * r2 + (((uint128_t) r4) * (d419   ));
    t[4] = ((uint128_t) d0) * r4 + ((uint128_t) d1) * r3 + (((uint128_t) r2) * (r2     ));

                    r0 = (limb)t[0] & 0x7ffffffffffff; c = (limb)(t[0] >> 51);
    t[1] += c;      r1 = (limb)t[1] & 0x7ffffffffffff; c = (limb)(t[1] >> 51);
    t[2] += c;      r2 = (limb)t[2] & 0x7ffffffffffff; c = (limb)(t[2] >> 51);
    t[3] += c;      r3 = (limb)t[3] & 0x7ffffffffffff; c = (limb)(t[3] >> 51);
    t[4] += c;      r4 = (limb)t[4] & 0x7ffffffffffff; c = (limb)(t[4] >> 51);
    r0 +=   c * 19; c = r0 >> 51; r0 = r0 & 0x7ffffffffffff;
    r1 +=   c;      c = r1 >> 51; r1 = r1 & 0x7ffffffffffff;
    r2 +=   c;
  } while(--count);

  output[0] = r0;
  output[1] = r1;
  output[2] = r2;
  output[3] = r3;
  output[4] = r4;
}

/* Load a little-endian 64-bit number  */
static limb
load_limb(const u8 *in) {
  return
    ((limb)in[0]) |
    (((limb)in[1]) << 8) |
    (((limb)in[2]) << 16) |
    (((limb)in[3]) << 24) |
    (((limb)in[4]) << 32) |
    (((limb)in[5]) << 40) |
    (((limb)in[6]) << 48) |
    (((limb)in[7]) << 56);
}

static void
store_limb(u8 *out, limb in) {
  out[0] = in & 0xff;
  out[1] = (in >> 8) & 0xff;
  out[2] = (in >> 16) & 0xff;
  out[3] = (in >> 24) & 0xff;
  out[4] = (in >> 32) & 0xff;
  out[5] = (in >> 40) & 0xff;
  out[6] = (in >> 48) & 0xff;
  out[7] = (in >> 56) & 0xff;
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
static void
fexpand(limb *output, const u8 *in) {
  output[0] = load_limb(in) & 0x7ffffffffffff;
  output[1] = (load_limb(in+6) >> 3) & 0x7ffffffffffff;
  output[2] = (load_limb(in+12) >> 6) & 0x7ffffffffffff;
  output[3] = (load_limb(in+19) >> 1) & 0x7ffffffffffff;
  output[4] = (load_limb(in+24) >> 12) & 0x7ffffffffffff;
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
static void
fcontract(u8 *output, const felem input) {
  uint128_t t[5];

  t[0] = input[0];
  t[1] = input[1];
  t[2] = input[2];
  t[3] = input[3];
  t[4] = input[4];

  t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
  t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
  t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
  t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
  t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffff;

  t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
  t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
  t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
  t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
  t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffff;

  /* now t is between 0 and 2^255-1, properly carried. */
  /* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */

  t[0] += 19;

  t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
  t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
  t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
  t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
  t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffff;

  /* now between 19 and 2^255-1 in both cases, and offset by 19. */

  t[0] += 0x8000000000000 - 19;
  t[1] += 0x8000000000000 - 1;
  t[2] += 0x8000000000000 - 1;
  t[3] += 0x8000000000000 - 1;
  t[4] += 0x8000000000000 - 1;

  /* now between 2^255 and 2^256-20, and offset by 2^255. */

  t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
  t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
  t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
  t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
  t[4] &= 0x7ffffffffffff;

  store_limb(output,    t[0] | (t[1] << 51));
  store_limb(output+8,  (t[1] >> 13) | (t[2] << 38));
  store_limb(output+16, (t[2] >> 26) | (t[3] << 25));
  store_limb(output+24, (t[3] >> 39) | (t[4] << 12));
}

/* Input: Q, Q', Q-Q'
 * Output: 2Q, Q+Q'
 *
 *   x2 z3: long form
 *   x3 z3: long form
 *   x z: short form, destroyed
 *   xprime zprime: short form, destroyed
 *   qmqp: short form, preserved
 */
static void
fmonty(limb *x2, limb *z2, /* output 2Q */
       limb *x3, limb *z3, /* output Q + Q' */
       limb *x, limb *z,   /* input Q */
       limb *xprime, limb *zprime, /* input Q' */
       const limb *qmqp /* input Q - Q' */) {

  uint64_t x14 =         0, x15 =         0, x16 =         0, x17 =         0, x18 =    121665;
  uint64_t x19 =   qmqp[4], x20 =   qmqp[3], x21 =   qmqp[2], x22 =   qmqp[1], x23 =   qmqp[0];
  uint64_t x24 =      x[4], x25 =      x[3], x26 =      x[2], x27 =      x[1], x28 =      x[0];
  uint64_t x29 =      z[4], x30 =      z[3], x31 =      z[2], x32 =      z[1], x33 =      z[0];
  uint64_t x34 = xprime[4], x35 = xprime[3], x36 = xprime[2], x37 = xprime[1], x38 = xprime[0];
  uint64_t x39 = zprime[4], x40 = zprime[3], x41 = zprime[2], x42 = zprime[1], x43 = zprime[0];

  uint64_t x44 = x24 + x29;
  uint64_t x45 = x25 + x30;
  uint64_t x46 = x26 + x31;
  uint64_t x47 = x27 + x32;
  uint64_t x48 = x28 + x33;
  uint128_t x49 = ((uint128_t) x48) * x48;
  uint128_t x50 = ((uint128_t) x44) * x47;
  uint128_t x51 = ((uint128_t) x45) * x46;
  uint128_t x52 = ((uint128_t) x46) * x45;
  uint128_t x53 = ((uint128_t) x47) * x44;
  uint128_t x54 = x52 + x53;
  uint128_t x55 = x51 + x54;
  uint128_t x56 = x50 + x55;
  uint8_t x57 = 0b00010011;
  uint128_t x58 = x57 * x56;
  uint128_t x59 = x49 + x58;
  uint8_t x60 = 0b00110011;
  uint64_t x61 = (uint64_t) (x59 >> x60);
  uint128_t x62 = ((uint128_t) x47) * x48;
  uint128_t x63 = ((uint128_t) x48) * x47;
  uint128_t x64 = x62 + x63;
  uint128_t x65 = ((uint128_t) x44) * x46;
  uint128_t x66 = ((uint128_t) x45) * x45;
  uint128_t x67 = ((uint128_t) x46) * x44;
  uint128_t x68 = x66 + x67;
  uint128_t x69 = x65 + x68;
  uint8_t x70 = 0b00010011;
  uint128_t x71 = x70 * x69;
  uint128_t x72 = x64 + x71;
  uint128_t x73 = x61 + x72;
  uint8_t x74 = 0b00110011;
  uint64_t x75 = (uint64_t) (x73 >> x74);
  uint128_t x76 = ((uint128_t) x46) * x48;
  uint128_t x77 = ((uint128_t) x47) * x47;
  uint128_t x78 = ((uint128_t) x48) * x46;
  uint128_t x79 = x77 + x78;
  uint128_t x80 = x76 + x79;
  uint128_t x81 = ((uint128_t) x44) * x45;
  uint128_t x82 = ((uint128_t) x45) * x44;
  uint128_t x83 = x81 + x82;
  uint8_t x84 = 0b00010011;
  uint128_t x85 = x84 * x83;
  uint128_t x86 = x80 + x85;
  uint128_t x87 = x75 + x86;
  uint8_t x88 = 0b00110011;
  uint64_t x89 = (uint64_t) (x87 >> x88);
  uint128_t x90 = ((uint128_t) x45) * x48;
  uint128_t x91 = ((uint128_t) x46) * x47;
  uint128_t x92 = ((uint128_t) x47) * x46;
  uint128_t x93 = ((uint128_t) x48) * x45;
  uint128_t x94 = x92 + x93;
  uint128_t x95 = x91 + x94;
  uint128_t x96 = x90 + x95;
  uint128_t x97 = ((uint128_t) x44) * x44;
  uint8_t x98 = 0b00010011;
  uint128_t x99 = x98 * x97;
  uint128_t x100 = x96 + x99;
  uint128_t x101 = x89 + x100;
  uint8_t x102 = 0b00110011;
  uint64_t x103 = (uint64_t) (x101 >> x102);
  uint128_t x104 = ((uint128_t) x44) * x48;
  uint128_t x105 = ((uint128_t) x45) * x47;
  uint128_t x106 = ((uint128_t) x46) * x46;
  uint128_t x107 = ((uint128_t) x47) * x45;
  uint128_t x108 = ((uint128_t) x48) * x44;
  uint128_t x109 = x107 + x108;
  uint128_t x110 = x106 + x109;
  uint128_t x111 = x105 + x110;
  uint128_t x112 = x104 + x111;
  uint128_t x113 = x103 + x112;
  uint8_t x114 = 0b00110011;
  uint64_t x115 = (uint64_t) (x113 >> x114);
  uint8_t x116 = 0b00010011;
  uint64_t x117 = x116 * x115;
  uint64_t x118 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x119 = x59 & x118;
  uint64_t x120 = x117 + x119;
  uint8_t x121 = 0b00110011;
  uint16_t x122 = (uint16_t) (x120 >> x121);
  uint64_t x123 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x124 = x73 & x123;
  uint64_t x125 = x122 + x124;
  uint64_t x126 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x127 = x113 & x126;
  uint64_t x128 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x129 = x101 & x128;
  uint8_t x130 = 0b00110011;
  bool x131 = (bool) (x125 >> x130);
  uint64_t x132 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x133 = x87 & x132;
  uint64_t x134 = x131 + x133;
  uint64_t x135 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x136 = x125 & x135;
  uint64_t x137 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x138 = x120 & x137;
  uint64_t x139 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x140 = x139 + x24;
  uint64_t x141 = x140 - x29;
  uint64_t x142 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x143 = x142 + x25;
  uint64_t x144 = x143 - x30;
  uint64_t x145 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x146 = x145 + x26;
  uint64_t x147 = x146 - x31;
  uint64_t x148 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x149 = x148 + x27;
  uint64_t x150 = x149 - x32;
  uint64_t x151 = 0b0000000000001111111111111111111111111111111111111111111111011010;
  uint64_t x152 = x151 + x28;
  uint64_t x153 = x152 - x33;
  uint128_t x154 = ((uint128_t) x153) * x153;
  uint128_t x155 = ((uint128_t) x141) * x150;
  uint128_t x156 = ((uint128_t) x144) * x147;
  uint128_t x157 = ((uint128_t) x147) * x144;
  uint128_t x158 = ((uint128_t) x150) * x141;
  uint128_t x159 = x157 + x158;
  uint128_t x160 = x156 + x159;
  uint128_t x161 = x155 + x160;
  uint8_t x162 = 0b00010011;
  uint128_t x163 = x162 * x161;
  uint128_t x164 = x154 + x163;
  uint8_t x165 = 0b00110011;
  uint64_t x166 = (uint64_t) (x164 >> x165);
  uint128_t x167 = ((uint128_t) x150) * x153;
  uint128_t x168 = ((uint128_t) x153) * x150;
  uint128_t x169 = x167 + x168;
  uint128_t x170 = ((uint128_t) x141) * x147;
  uint128_t x171 = ((uint128_t) x144) * x144;
  uint128_t x172 = ((uint128_t) x147) * x141;
  uint128_t x173 = x171 + x172;
  uint128_t x174 = x170 + x173;
  uint8_t x175 = 0b00010011;
  uint128_t x176 = x175 * x174;
  uint128_t x177 = x169 + x176;
  uint128_t x178 = x166 + x177;
  uint8_t x179 = 0b00110011;
  uint64_t x180 = (uint64_t) (x178 >> x179);
  uint128_t x181 = ((uint128_t) x147) * x153;
  uint128_t x182 = ((uint128_t) x150) * x150;
  uint128_t x183 = ((uint128_t) x153) * x147;
  uint128_t x184 = x182 + x183;
  uint128_t x185 = x181 + x184;
  uint128_t x186 = ((uint128_t) x141) * x144;
  uint128_t x187 = ((uint128_t) x144) * x141;
  uint128_t x188 = x186 + x187;
  uint8_t x189 = 0b00010011;
  uint128_t x190 = x189 * x188;
  uint128_t x191 = x185 + x190;
  uint128_t x192 = x180 + x191;
  uint8_t x193 = 0b00110011;
  uint64_t x194 = (uint64_t) (x192 >> x193);
  uint128_t x195 = ((uint128_t) x144) * x153;
  uint128_t x196 = ((uint128_t) x147) * x150;
  uint128_t x197 = ((uint128_t) x150) * x147;
  uint128_t x198 = ((uint128_t) x153) * x144;
  uint128_t x199 = x197 + x198;
  uint128_t x200 = x196 + x199;
  uint128_t x201 = x195 + x200;
  uint128_t x202 = ((uint128_t) x141) * x141;
  uint8_t x203 = 0b00010011;
  uint128_t x204 = x203 * x202;
  uint128_t x205 = x201 + x204;
  uint128_t x206 = x194 + x205;
  uint8_t x207 = 0b00110011;
  uint64_t x208 = (uint64_t) (x206 >> x207);
  uint128_t x209 = ((uint128_t) x141) * x153;
  uint128_t x210 = ((uint128_t) x144) * x150;
  uint128_t x211 = ((uint128_t) x147) * x147;
  uint128_t x212 = ((uint128_t) x150) * x144;
  uint128_t x213 = ((uint128_t) x153) * x141;
  uint128_t x214 = x212 + x213;
  uint128_t x215 = x211 + x214;
  uint128_t x216 = x210 + x215;
  uint128_t x217 = x209 + x216;
  uint128_t x218 = x208 + x217;
  uint8_t x219 = 0b00110011;
  uint64_t x220 = (uint64_t) (x218 >> x219);
  uint8_t x221 = 0b00010011;
  uint64_t x222 = x221 * x220;
  uint64_t x223 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x224 = x164 & x223;
  uint64_t x225 = x222 + x224;
  uint8_t x226 = 0b00110011;
  uint16_t x227 = (uint16_t) (x225 >> x226);
  uint64_t x228 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x229 = x178 & x228;
  uint64_t x230 = x227 + x229;
  uint64_t x231 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x232 = x218 & x231;
  uint64_t x233 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x234 = x206 & x233;
  uint8_t x235 = 0b00110011;
  bool x236 = (bool) (x230 >> x235);
  uint64_t x237 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x238 = x192 & x237;
  uint64_t x239 = x236 + x238;
  uint64_t x240 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x241 = x230 & x240;
  uint64_t x242 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x243 = x225 & x242;
  uint64_t x244 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x245 = x244 + x127;
  uint64_t x246 = x245 - x232;
  uint64_t x247 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x248 = x247 + x129;
  uint64_t x249 = x248 - x234;
  uint64_t x250 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x251 = x250 + x134;
  uint64_t x252 = x251 - x239;
  uint64_t x253 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x254 = x253 + x136;
  uint64_t x255 = x254 - x241;
  uint64_t x256 = 0b0000000000001111111111111111111111111111111111111111111111011010;
  uint64_t x257 = x256 + x138;
  uint64_t x258 = x257 - x243;
  uint64_t x259 = x34 + x39;
  uint64_t x260 = x35 + x40;
  uint64_t x261 = x36 + x41;
  uint64_t x262 = x37 + x42;
  uint64_t x263 = x38 + x43;
  uint64_t x264 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x265 = x264 + x34;
  uint64_t x266 = x265 - x39;
  uint64_t x267 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x268 = x267 + x35;
  uint64_t x269 = x268 - x40;
  uint64_t x270 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x271 = x270 + x36;
  uint64_t x272 = x271 - x41;
  uint64_t x273 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x274 = x273 + x37;
  uint64_t x275 = x274 - x42;
  uint64_t x276 = 0b0000000000001111111111111111111111111111111111111111111111011010;
  uint64_t x277 = x276 + x38;
  uint64_t x278 = x277 - x43;
  uint128_t x279 = ((uint128_t) x278) * x48;
  uint128_t x280 = ((uint128_t) x266) * x47;
  uint128_t x281 = ((uint128_t) x269) * x46;
  uint128_t x282 = ((uint128_t) x272) * x45;
  uint128_t x283 = ((uint128_t) x275) * x44;
  uint128_t x284 = x282 + x283;
  uint128_t x285 = x281 + x284;
  uint128_t x286 = x280 + x285;
  uint8_t x287 = 0b00010011;
  uint128_t x288 = x287 * x286;
  uint128_t x289 = x279 + x288;
  uint8_t x290 = 0b00110011;
  uint64_t x291 = (uint64_t) (x289 >> x290);
  uint128_t x292 = ((uint128_t) x275) * x48;
  uint128_t x293 = ((uint128_t) x278) * x47;
  uint128_t x294 = x292 + x293;
  uint128_t x295 = ((uint128_t) x266) * x46;
  uint128_t x296 = ((uint128_t) x269) * x45;
  uint128_t x297 = ((uint128_t) x272) * x44;
  uint128_t x298 = x296 + x297;
  uint128_t x299 = x295 + x298;
  uint8_t x300 = 0b00010011;
  uint128_t x301 = x300 * x299;
  uint128_t x302 = x294 + x301;
  uint128_t x303 = x291 + x302;
  uint8_t x304 = 0b00110011;
  uint64_t x305 = (uint64_t) (x303 >> x304);
  uint128_t x306 = ((uint128_t) x272) * x48;
  uint128_t x307 = ((uint128_t) x275) * x47;
  uint128_t x308 = ((uint128_t) x278) * x46;
  uint128_t x309 = x307 + x308;
  uint128_t x310 = x306 + x309;
  uint128_t x311 = ((uint128_t) x266) * x45;
  uint128_t x312 = ((uint128_t) x269) * x44;
  uint128_t x313 = x311 + x312;
  uint8_t x314 = 0b00010011;
  uint128_t x315 = x314 * x313;
  uint128_t x316 = x310 + x315;
  uint128_t x317 = x305 + x316;
  uint8_t x318 = 0b00110011;
  uint64_t x319 = (uint64_t) (x317 >> x318);
  uint128_t x320 = ((uint128_t) x269) * x48;
  uint128_t x321 = ((uint128_t) x272) * x47;
  uint128_t x322 = ((uint128_t) x275) * x46;
  uint128_t x323 = ((uint128_t) x278) * x45;
  uint128_t x324 = x322 + x323;
  uint128_t x325 = x321 + x324;
  uint128_t x326 = x320 + x325;
  uint128_t x327 = ((uint128_t) x266) * x44;
  uint8_t x328 = 0b00010011;
  uint128_t x329 = x328 * x327;
  uint128_t x330 = x326 + x329;
  uint128_t x331 = x319 + x330;
  uint8_t x332 = 0b00110011;
  uint64_t x333 = (uint64_t) (x331 >> x332);
  uint128_t x334 = ((uint128_t) x266) * x48;
  uint128_t x335 = ((uint128_t) x269) * x47;
  uint128_t x336 = ((uint128_t) x272) * x46;
  uint128_t x337 = ((uint128_t) x275) * x45;
  uint128_t x338 = ((uint128_t) x278) * x44;
  uint128_t x339 = x337 + x338;
  uint128_t x340 = x336 + x339;
  uint128_t x341 = x335 + x340;
  uint128_t x342 = x334 + x341;
  uint128_t x343 = x333 + x342;
  uint8_t x344 = 0b00110011;
  uint64_t x345 = (uint64_t) (x343 >> x344);
  uint8_t x346 = 0b00010011;
  uint64_t x347 = x346 * x345;
  uint64_t x348 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x349 = x289 & x348;
  uint64_t x350 = x347 + x349;
  uint8_t x351 = 0b00110011;
  uint16_t x352 = (uint16_t) (x350 >> x351);
  uint64_t x353 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x354 = x303 & x353;
  uint64_t x355 = x352 + x354;
  uint64_t x356 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x357 = x343 & x356;
  uint64_t x358 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x359 = x331 & x358;
  uint8_t x360 = 0b00110011;
  bool x361 = (bool) (x355 >> x360);
  uint64_t x362 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x363 = x317 & x362;
  uint64_t x364 = x361 + x363;
  uint64_t x365 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x366 = x355 & x365;
  uint64_t x367 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x368 = x350 & x367;
  uint128_t x369 = ((uint128_t) x263) * x153;
  uint128_t x370 = ((uint128_t) x259) * x150;
  uint128_t x371 = ((uint128_t) x260) * x147;
  uint128_t x372 = ((uint128_t) x261) * x144;
  uint128_t x373 = ((uint128_t) x262) * x141;
  uint128_t x374 = x372 + x373;
  uint128_t x375 = x371 + x374;
  uint128_t x376 = x370 + x375;
  uint8_t x377 = 0b00010011;
  uint128_t x378 = x377 * x376;
  uint128_t x379 = x369 + x378;
  uint8_t x380 = 0b00110011;
  uint64_t x381 = (uint64_t) (x379 >> x380);
  uint128_t x382 = ((uint128_t) x262) * x153;
  uint128_t x383 = ((uint128_t) x263) * x150;
  uint128_t x384 = x382 + x383;
  uint128_t x385 = ((uint128_t) x259) * x147;
  uint128_t x386 = ((uint128_t) x260) * x144;
  uint128_t x387 = ((uint128_t) x261) * x141;
  uint128_t x388 = x386 + x387;
  uint128_t x389 = x385 + x388;
  uint8_t x390 = 0b00010011;
  uint128_t x391 = x390 * x389;
  uint128_t x392 = x384 + x391;
  uint128_t x393 = x381 + x392;
  uint8_t x394 = 0b00110011;
  uint64_t x395 = (uint64_t) (x393 >> x394);
  uint128_t x396 = ((uint128_t) x261) * x153;
  uint128_t x397 = ((uint128_t) x262) * x150;
  uint128_t x398 = ((uint128_t) x263) * x147;
  uint128_t x399 = x397 + x398;
  uint128_t x400 = x396 + x399;
  uint128_t x401 = ((uint128_t) x259) * x144;
  uint128_t x402 = ((uint128_t) x260) * x141;
  uint128_t x403 = x401 + x402;
  uint8_t x404 = 0b00010011;
  uint128_t x405 = x404 * x403;
  uint128_t x406 = x400 + x405;
  uint128_t x407 = x395 + x406;
  uint8_t x408 = 0b00110011;
  uint64_t x409 = (uint64_t) (x407 >> x408);
  uint128_t x410 = ((uint128_t) x260) * x153;
  uint128_t x411 = ((uint128_t) x261) * x150;
  uint128_t x412 = ((uint128_t) x262) * x147;
  uint128_t x413 = ((uint128_t) x263) * x144;
  uint128_t x414 = x412 + x413;
  uint128_t x415 = x411 + x414;
  uint128_t x416 = x410 + x415;
  uint128_t x417 = ((uint128_t) x259) * x141;
  uint8_t x418 = 0b00010011;
  uint128_t x419 = x418 * x417;
  uint128_t x420 = x416 + x419;
  uint128_t x421 = x409 + x420;
  uint8_t x422 = 0b00110011;
  uint64_t x423 = (uint64_t) (x421 >> x422);
  uint128_t x424 = ((uint128_t) x259) * x153;
  uint128_t x425 = ((uint128_t) x260) * x150;
  uint128_t x426 = ((uint128_t) x261) * x147;
  uint128_t x427 = ((uint128_t) x262) * x144;
  uint128_t x428 = ((uint128_t) x263) * x141;
  uint128_t x429 = x427 + x428;
  uint128_t x430 = x426 + x429;
  uint128_t x431 = x425 + x430;
  uint128_t x432 = x424 + x431;
  uint128_t x433 = x423 + x432;
  uint8_t x434 = 0b00110011;
  uint64_t x435 = (uint64_t) (x433 >> x434);
  uint8_t x436 = 0b00010011;
  uint64_t x437 = x436 * x435;
  uint64_t x438 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x439 = x379 & x438;
  uint64_t x440 = x437 + x439;
  uint8_t x441 = 0b00110011;
  uint16_t x442 = (uint16_t) (x440 >> x441);
  uint64_t x443 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x444 = x393 & x443;
  uint64_t x445 = x442 + x444;
  uint64_t x446 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x447 = x433 & x446;
  uint64_t x448 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x449 = x421 & x448;
  uint8_t x450 = 0b00110011;
  bool x451 = (bool) (x445 >> x450);
  uint64_t x452 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x453 = x407 & x452;
  uint64_t x454 = x451 + x453;
  uint64_t x455 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x456 = x445 & x455;
  uint64_t x457 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x458 = x440 & x457;
  uint64_t x459 = x357 + x447;
  uint64_t x460 = x359 + x449;
  uint64_t x461 = x364 + x454;
  uint64_t x462 = x366 + x456;
  uint64_t x463 = x368 + x458;
  uint64_t x464 = x357 + x447;
  uint64_t x465 = x359 + x449;
  uint64_t x466 = x364 + x454;
  uint64_t x467 = x366 + x456;
  uint64_t x468 = x368 + x458;
  uint128_t x469 = ((uint128_t) x463) * x468;
  uint128_t x470 = ((uint128_t) x459) * x467;
  uint128_t x471 = ((uint128_t) x460) * x466;
  uint128_t x472 = ((uint128_t) x461) * x465;
  uint128_t x473 = ((uint128_t) x462) * x464;
  uint128_t x474 = x472 + x473;
  uint128_t x475 = x471 + x474;
  uint128_t x476 = x470 + x475;
  uint8_t x477 = 0b00010011;
  uint128_t x478 = x477 * x476;
  uint128_t x479 = x469 + x478;
  uint8_t x480 = 0b00110011;
  uint64_t x481 = (uint64_t) (x479 >> x480);
  uint128_t x482 = ((uint128_t) x462) * x468;
  uint128_t x483 = ((uint128_t) x463) * x467;
  uint128_t x484 = x482 + x483;
  uint128_t x485 = ((uint128_t) x459) * x466;
  uint128_t x486 = ((uint128_t) x460) * x465;
  uint128_t x487 = ((uint128_t) x461) * x464;
  uint128_t x488 = x486 + x487;
  uint128_t x489 = x485 + x488;
  uint8_t x490 = 0b00010011;
  uint128_t x491 = x490 * x489;
  uint128_t x492 = x484 + x491;
  uint128_t x493 = x481 + x492;
  uint8_t x494 = 0b00110011;
  uint64_t x495 = (uint64_t) (x493 >> x494);
  uint128_t x496 = ((uint128_t) x461) * x468;
  uint128_t x497 = ((uint128_t) x462) * x467;
  uint128_t x498 = ((uint128_t) x463) * x466;
  uint128_t x499 = x497 + x498;
  uint128_t x500 = x496 + x499;
  uint128_t x501 = ((uint128_t) x459) * x465;
  uint128_t x502 = ((uint128_t) x460) * x464;
  uint128_t x503 = x501 + x502;
  uint8_t x504 = 0b00010011;
  uint128_t x505 = x504 * x503;
  uint128_t x506 = x500 + x505;
  uint128_t x507 = x495 + x506;
  uint8_t x508 = 0b00110011;
  uint64_t x509 = (uint64_t) (x507 >> x508);
  uint128_t x510 = ((uint128_t) x460) * x468;
  uint128_t x511 = ((uint128_t) x461) * x467;
  uint128_t x512 = ((uint128_t) x462) * x466;
  uint128_t x513 = ((uint128_t) x463) * x465;
  uint128_t x514 = x512 + x513;
  uint128_t x515 = x511 + x514;
  uint128_t x516 = x510 + x515;
  uint128_t x517 = ((uint128_t) x459) * x464;
  uint8_t x518 = 0b00010011;
  uint128_t x519 = x518 * x517;
  uint128_t x520 = x516 + x519;
  uint128_t x521 = x509 + x520;
  uint8_t x522 = 0b00110011;
  uint64_t x523 = (uint64_t) (x521 >> x522);
  uint128_t x524 = ((uint128_t) x459) * x468;
  uint128_t x525 = ((uint128_t) x460) * x467;
  uint128_t x526 = ((uint128_t) x461) * x466;
  uint128_t x527 = ((uint128_t) x462) * x465;
  uint128_t x528 = ((uint128_t) x463) * x464;
  uint128_t x529 = x527 + x528;
  uint128_t x530 = x526 + x529;
  uint128_t x531 = x525 + x530;
  uint128_t x532 = x524 + x531;
  uint128_t x533 = x523 + x532;
  uint8_t x534 = 0b00110011;
  uint64_t x535 = (uint64_t) (x533 >> x534);
  uint8_t x536 = 0b00010011;
  uint64_t x537 = x536 * x535;
  uint64_t x538 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x539 = x479 & x538;
  uint64_t x540 = x537 + x539;
  uint8_t x541 = 0b00110011;
  uint16_t x542 = (uint16_t) (x540 >> x541);
  uint64_t x543 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x544 = x493 & x543;
  uint64_t x545 = x542 + x544;
  uint64_t x546 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x547 = x533 & x546;
  uint64_t x548 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x549 = x521 & x548;
  uint8_t x550 = 0b00110011;
  bool x551 = (bool) (x545 >> x550);
  uint64_t x552 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x553 = x507 & x552;
  uint64_t x554 = x551 + x553;
  uint64_t x555 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x556 = x545 & x555;
  uint64_t x557 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x558 = x540 & x557;
  uint64_t x559 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x560 = x559 + x357;
  uint64_t x561 = x560 - x447;
  uint64_t x562 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x563 = x562 + x359;
  uint64_t x564 = x563 - x449;
  uint64_t x565 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x566 = x565 + x364;
  uint64_t x567 = x566 - x454;
  uint64_t x568 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x569 = x568 + x366;
  uint64_t x570 = x569 - x456;
  uint64_t x571 = 0b0000000000001111111111111111111111111111111111111111111111011010;
  uint64_t x572 = x571 + x368;
  uint64_t x573 = x572 - x458;
  uint64_t x574 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x575 = x574 + x357;
  uint64_t x576 = x575 - x447;
  uint64_t x577 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x578 = x577 + x359;
  uint64_t x579 = x578 - x449;
  uint64_t x580 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x581 = x580 + x364;
  uint64_t x582 = x581 - x454;
  uint64_t x583 = 0b0000000000001111111111111111111111111111111111111111111111111110;
  uint64_t x584 = x583 + x366;
  uint64_t x585 = x584 - x456;
  uint64_t x586 = 0b0000000000001111111111111111111111111111111111111111111111011010;
  uint64_t x587 = x586 + x368;
  uint64_t x588 = x587 - x458;
  uint128_t x589 = ((uint128_t) x573) * x588;
  uint128_t x590 = ((uint128_t) x561) * x585;
  uint128_t x591 = ((uint128_t) x564) * x582;
  uint128_t x592 = ((uint128_t) x567) * x579;
  uint128_t x593 = ((uint128_t) x570) * x576;
  uint128_t x594 = x592 + x593;
  uint128_t x595 = x591 + x594;
  uint128_t x596 = x590 + x595;
  uint8_t x597 = 0b00010011;
  uint128_t x598 = x597 * x596;
  uint128_t x599 = x589 + x598;
  uint8_t x600 = 0b00110011;
  uint64_t x601 = (uint64_t) (x599 >> x600);
  uint128_t x602 = ((uint128_t) x570) * x588;
  uint128_t x603 = ((uint128_t) x573) * x585;
  uint128_t x604 = x602 + x603;
  uint128_t x605 = ((uint128_t) x561) * x582;
  uint128_t x606 = ((uint128_t) x564) * x579;
  uint128_t x607 = ((uint128_t) x567) * x576;
  uint128_t x608 = x606 + x607;
  uint128_t x609 = x605 + x608;
  uint8_t x610 = 0b00010011;
  uint128_t x611 = x610 * x609;
  uint128_t x612 = x604 + x611;
  uint128_t x613 = x601 + x612;
  uint8_t x614 = 0b00110011;
  uint64_t x615 = (uint64_t) (x613 >> x614);
  uint128_t x616 = ((uint128_t) x567) * x588;
  uint128_t x617 = ((uint128_t) x570) * x585;
  uint128_t x618 = ((uint128_t) x573) * x582;
  uint128_t x619 = x617 + x618;
  uint128_t x620 = x616 + x619;
  uint128_t x621 = ((uint128_t) x561) * x579;
  uint128_t x622 = ((uint128_t) x564) * x576;
  uint128_t x623 = x621 + x622;
  uint8_t x624 = 0b00010011;
  uint128_t x625 = x624 * x623;
  uint128_t x626 = x620 + x625;
  uint128_t x627 = x615 + x626;
  uint8_t x628 = 0b00110011;
  uint64_t x629 = (uint64_t) (x627 >> x628);
  uint128_t x630 = ((uint128_t) x564) * x588;
  uint128_t x631 = ((uint128_t) x567) * x585;
  uint128_t x632 = ((uint128_t) x570) * x582;
  uint128_t x633 = ((uint128_t) x573) * x579;
  uint128_t x634 = x632 + x633;
  uint128_t x635 = x631 + x634;
  uint128_t x636 = x630 + x635;
  uint128_t x637 = ((uint128_t) x561) * x576;
  uint8_t x638 = 0b00010011;
  uint128_t x639 = x638 * x637;
  uint128_t x640 = x636 + x639;
  uint128_t x641 = x629 + x640;
  uint8_t x642 = 0b00110011;
  uint64_t x643 = (uint64_t) (x641 >> x642);
  uint128_t x644 = ((uint128_t) x561) * x588;
  uint128_t x645 = ((uint128_t) x564) * x585;
  uint128_t x646 = ((uint128_t) x567) * x582;
  uint128_t x647 = ((uint128_t) x570) * x579;
  uint128_t x648 = ((uint128_t) x573) * x576;
  uint128_t x649 = x647 + x648;
  uint128_t x650 = x646 + x649;
  uint128_t x651 = x645 + x650;
  uint128_t x652 = x644 + x651;
  uint128_t x653 = x643 + x652;
  uint8_t x654 = 0b00110011;
  uint64_t x655 = (uint64_t) (x653 >> x654);
  uint8_t x656 = 0b00010011;
  uint64_t x657 = x656 * x655;
  uint64_t x658 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x659 = x599 & x658;
  uint64_t x660 = x657 + x659;
  uint8_t x661 = 0b00110011;
  uint16_t x662 = (uint16_t) (x660 >> x661);
  uint64_t x663 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x664 = x613 & x663;
  uint64_t x665 = x662 + x664;
  uint64_t x666 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x667 = x653 & x666;
  uint64_t x668 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x669 = x641 & x668;
  uint8_t x670 = 0b00110011;
  bool x671 = (bool) (x665 >> x670);
  uint64_t x672 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x673 = x627 & x672;
  uint64_t x674 = x671 + x673;
  uint64_t x675 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x676 = x665 & x675;
  uint64_t x677 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x678 = x660 & x677;
  uint128_t x679 = ((uint128_t) x23) * x678;
  uint128_t x680 = ((uint128_t) x19) * x676;
  uint128_t x681 = ((uint128_t) x20) * x674;
  uint128_t x682 = ((uint128_t) x21) * x669;
  uint128_t x683 = ((uint128_t) x22) * x667;
  uint128_t x684 = x682 + x683;
  uint128_t x685 = x681 + x684;
  uint128_t x686 = x680 + x685;
  uint8_t x687 = 0b00010011;
  uint128_t x688 = x687 * x686;
  uint128_t x689 = x679 + x688;
  uint8_t x690 = 0b00110011;
  uint64_t x691 = (uint64_t) (x689 >> x690);
  uint128_t x692 = ((uint128_t) x22) * x678;
  uint128_t x693 = ((uint128_t) x23) * x676;
  uint128_t x694 = x692 + x693;
  uint128_t x695 = ((uint128_t) x19) * x674;
  uint128_t x696 = ((uint128_t) x20) * x669;
  uint128_t x697 = ((uint128_t) x21) * x667;
  uint128_t x698 = x696 + x697;
  uint128_t x699 = x695 + x698;
  uint8_t x700 = 0b00010011;
  uint128_t x701 = x700 * x699;
  uint128_t x702 = x694 + x701;
  uint128_t x703 = x691 + x702;
  uint8_t x704 = 0b00110011;
  uint64_t x705 = (uint64_t) (x703 >> x704);
  uint128_t x706 = ((uint128_t) x21) * x678;
  uint128_t x707 = ((uint128_t) x22) * x676;
  uint128_t x708 = ((uint128_t) x23) * x674;
  uint128_t x709 = x707 + x708;
  uint128_t x710 = x706 + x709;
  uint128_t x711 = ((uint128_t) x19) * x669;
  uint128_t x712 = ((uint128_t) x20) * x667;
  uint128_t x713 = x711 + x712;
  uint8_t x714 = 0b00010011;
  uint128_t x715 = x714 * x713;
  uint128_t x716 = x710 + x715;
  uint128_t x717 = x705 + x716;
  uint8_t x718 = 0b00110011;
  uint64_t x719 = (uint64_t) (x717 >> x718);
  uint128_t x720 = ((uint128_t) x20) * x678;
  uint128_t x721 = ((uint128_t) x21) * x676;
  uint128_t x722 = ((uint128_t) x22) * x674;
  uint128_t x723 = ((uint128_t) x23) * x669;
  uint128_t x724 = x722 + x723;
  uint128_t x725 = x721 + x724;
  uint128_t x726 = x720 + x725;
  uint128_t x727 = ((uint128_t) x19) * x667;
  uint8_t x728 = 0b00010011;
  uint128_t x729 = x728 * x727;
  uint128_t x730 = x726 + x729;
  uint128_t x731 = x719 + x730;
  uint8_t x732 = 0b00110011;
  uint64_t x733 = (uint64_t) (x731 >> x732);
  uint128_t x734 = ((uint128_t) x19) * x678;
  uint128_t x735 = ((uint128_t) x20) * x676;
  uint128_t x736 = ((uint128_t) x21) * x674;
  uint128_t x737 = ((uint128_t) x22) * x669;
  uint128_t x738 = ((uint128_t) x23) * x667;
  uint128_t x739 = x737 + x738;
  uint128_t x740 = x736 + x739;
  uint128_t x741 = x735 + x740;
  uint128_t x742 = x734 + x741;
  uint128_t x743 = x733 + x742;
  uint8_t x744 = 0b00110011;
  uint64_t x745 = (uint64_t) (x743 >> x744);
  uint8_t x746 = 0b00010011;
  uint64_t x747 = x746 * x745;
  uint64_t x748 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x749 = x689 & x748;
  uint64_t x750 = x747 + x749;
  uint8_t x751 = 0b00110011;
  uint8_t x752 = (uint8_t) (x750 >> x751);
  uint64_t x753 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x754 = x703 & x753;
  uint64_t x755 = x752 + x754;
  uint64_t x756 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x757 = x743 & x756;
  uint64_t x758 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x759 = x731 & x758;
  uint8_t x760 = 0b00110011;
  bool x761 = (bool) (x755 >> x760);
  uint64_t x762 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x763 = x717 & x762;
  uint64_t x764 = x761 + x763;
  uint64_t x765 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x766 = x755 & x765;
  uint64_t x767 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x768 = x750 & x767;
  uint128_t x769 = ((uint128_t) x138) * x243;
  uint128_t x770 = ((uint128_t) x127) * x241;
  uint128_t x771 = ((uint128_t) x129) * x239;
  uint128_t x772 = ((uint128_t) x134) * x234;
  uint128_t x773 = ((uint128_t) x136) * x232;
  uint128_t x774 = x772 + x773;
  uint128_t x775 = x771 + x774;
  uint128_t x776 = x770 + x775;
  uint8_t x777 = 0b00010011;
  uint128_t x778 = x777 * x776;
  uint128_t x779 = x769 + x778;
  uint8_t x780 = 0b00110011;
  uint64_t x781 = (uint64_t) (x779 >> x780);
  uint128_t x782 = ((uint128_t) x136) * x243;
  uint128_t x783 = ((uint128_t) x138) * x241;
  uint128_t x784 = x782 + x783;
  uint128_t x785 = ((uint128_t) x127) * x239;
  uint128_t x786 = ((uint128_t) x129) * x234;
  uint128_t x787 = ((uint128_t) x134) * x232;
  uint128_t x788 = x786 + x787;
  uint128_t x789 = x785 + x788;
  uint8_t x790 = 0b00010011;
  uint128_t x791 = x790 * x789;
  uint128_t x792 = x784 + x791;
  uint128_t x793 = x781 + x792;
  uint8_t x794 = 0b00110011;
  uint64_t x795 = (uint64_t) (x793 >> x794);
  uint128_t x796 = ((uint128_t) x134) * x243;
  uint128_t x797 = ((uint128_t) x136) * x241;
  uint128_t x798 = ((uint128_t) x138) * x239;
  uint128_t x799 = x797 + x798;
  uint128_t x800 = x796 + x799;
  uint128_t x801 = ((uint128_t) x127) * x234;
  uint128_t x802 = ((uint128_t) x129) * x232;
  uint128_t x803 = x801 + x802;
  uint8_t x804 = 0b00010011;
  uint128_t x805 = x804 * x803;
  uint128_t x806 = x800 + x805;
  uint128_t x807 = x795 + x806;
  uint8_t x808 = 0b00110011;
  uint64_t x809 = (uint64_t) (x807 >> x808);
  uint128_t x810 = ((uint128_t) x129) * x243;
  uint128_t x811 = ((uint128_t) x134) * x241;
  uint128_t x812 = ((uint128_t) x136) * x239;
  uint128_t x813 = ((uint128_t) x138) * x234;
  uint128_t x814 = x812 + x813;
  uint128_t x815 = x811 + x814;
  uint128_t x816 = x810 + x815;
  uint128_t x817 = ((uint128_t) x127) * x232;
  uint8_t x818 = 0b00010011;
  uint128_t x819 = x818 * x817;
  uint128_t x820 = x816 + x819;
  uint128_t x821 = x809 + x820;
  uint8_t x822 = 0b00110011;
  uint64_t x823 = (uint64_t) (x821 >> x822);
  uint128_t x824 = ((uint128_t) x127) * x243;
  uint128_t x825 = ((uint128_t) x129) * x241;
  uint128_t x826 = ((uint128_t) x134) * x239;
  uint128_t x827 = ((uint128_t) x136) * x234;
  uint128_t x828 = ((uint128_t) x138) * x232;
  uint128_t x829 = x827 + x828;
  uint128_t x830 = x826 + x829;
  uint128_t x831 = x825 + x830;
  uint128_t x832 = x824 + x831;
  uint128_t x833 = x823 + x832;
  uint8_t x834 = 0b00110011;
  uint64_t x835 = (uint64_t) (x833 >> x834);
  uint8_t x836 = 0b00010011;
  uint64_t x837 = x836 * x835;
  uint64_t x838 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x839 = x779 & x838;
  uint64_t x840 = x837 + x839;
  uint8_t x841 = 0b00110011;
  uint8_t x842 = (uint8_t) (x840 >> x841);
  uint64_t x843 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x844 = x793 & x843;
  uint64_t x845 = x842 + x844;
  uint64_t x846 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x847 = x833 & x846;
  uint64_t x848 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x849 = x821 & x848;
  uint8_t x850 = 0b00110011;
  bool x851 = (bool) (x845 >> x850);
  uint64_t x852 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x853 = x807 & x852;
  uint64_t x854 = x851 + x853;
  uint64_t x855 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x856 = x845 & x855;
  uint64_t x857 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x858 = x840 & x857;
  uint128_t x859 = ((uint128_t) x18) * x258;
  uint128_t x860 = ((uint128_t) x14) * x255;
  uint128_t x861 = ((uint128_t) x15) * x252;
  uint128_t x862 = ((uint128_t) x16) * x249;
  uint128_t x863 = ((uint128_t) x17) * x246;
  uint128_t x864 = x862 + x863;
  uint128_t x865 = x861 + x864;
  uint128_t x866 = x860 + x865;
  uint8_t x867 = 0b00010011;
  uint128_t x868 = x867 * x866;
  uint128_t x869 = x859 + x868;
  uint8_t x870 = 0b00110011;
  uint64_t x871 = (uint64_t) (x869 >> x870);
  uint128_t x872 = ((uint128_t) x17) * x258;
  uint128_t x873 = ((uint128_t) x18) * x255;
  uint128_t x874 = x872 + x873;
  uint128_t x875 = ((uint128_t) x14) * x252;
  uint128_t x876 = ((uint128_t) x15) * x249;
  uint128_t x877 = ((uint128_t) x16) * x246;
  uint128_t x878 = x876 + x877;
  uint128_t x879 = x875 + x878;
  uint8_t x880 = 0b00010011;
  uint128_t x881 = x880 * x879;
  uint128_t x882 = x874 + x881;
  uint128_t x883 = x871 + x882;
  uint8_t x884 = 0b00110011;
  uint64_t x885 = (uint64_t) (x883 >> x884);
  uint128_t x886 = ((uint128_t) x16) * x258;
  uint128_t x887 = ((uint128_t) x17) * x255;
  uint128_t x888 = ((uint128_t) x18) * x252;
  uint128_t x889 = x887 + x888;
  uint128_t x890 = x886 + x889;
  uint128_t x891 = ((uint128_t) x14) * x249;
  uint128_t x892 = ((uint128_t) x15) * x246;
  uint128_t x893 = x891 + x892;
  uint8_t x894 = 0b00010011;
  uint128_t x895 = x894 * x893;
  uint128_t x896 = x890 + x895;
  uint128_t x897 = x885 + x896;
  uint8_t x898 = 0b00110011;
  uint64_t x899 = (uint64_t) (x897 >> x898);
  uint128_t x900 = ((uint128_t) x15) * x258;
  uint128_t x901 = ((uint128_t) x16) * x255;
  uint128_t x902 = ((uint128_t) x17) * x252;
  uint128_t x903 = ((uint128_t) x18) * x249;
  uint128_t x904 = x902 + x903;
  uint128_t x905 = x901 + x904;
  uint128_t x906 = x900 + x905;
  uint128_t x907 = ((uint128_t) x14) * x246;
  uint8_t x908 = 0b00010011;
  uint128_t x909 = x908 * x907;
  uint128_t x910 = x906 + x909;
  uint128_t x911 = x899 + x910;
  uint8_t x912 = 0b00110011;
  uint64_t x913 = (uint64_t) (x911 >> x912);
  uint128_t x914 = ((uint128_t) x14) * x258;
  uint128_t x915 = ((uint128_t) x15) * x255;
  uint128_t x916 = ((uint128_t) x16) * x252;
  uint128_t x917 = ((uint128_t) x17) * x249;
  uint128_t x918 = ((uint128_t) x18) * x246;
  uint128_t x919 = x917 + x918;
  uint128_t x920 = x916 + x919;
  uint128_t x921 = x915 + x920;
  uint128_t x922 = x914 + x921;
  uint128_t x923 = x913 + x922;
  uint8_t x924 = 0b00110011;
  uint64_t x925 = (uint64_t) (x923 >> x924);
  uint8_t x926 = 0b00010011;
  uint64_t x927 = x926 * x925;
  uint64_t x928 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x929 = x869 & x928;
  uint64_t x930 = x927 + x929;
  uint8_t x931 = 0b00110011;
  uint16_t x932 = (uint16_t) (x930 >> x931);
  uint64_t x933 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x934 = x883 & x933;
  uint64_t x935 = x932 + x934;
  uint64_t x936 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x937 = x923 & x936;
  uint64_t x938 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x939 = x911 & x938;
  uint8_t x940 = 0b00110011;
  bool x941 = (bool) (x935 >> x940);
  uint64_t x942 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x943 = x897 & x942;
  uint64_t x944 = x941 + x943;
  uint64_t x945 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x946 = x935 & x945;
  uint64_t x947 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x948 = x930 & x947;
  uint64_t x949 = x127 + x937;
  uint64_t x950 = x129 + x939;
  uint64_t x951 = x134 + x944;
  uint64_t x952 = x136 + x946;
  uint64_t x953 = x138 + x948;
  uint128_t x954 = ((uint128_t) x258) * x953;
  uint128_t x955 = ((uint128_t) x246) * x952;
  uint128_t x956 = ((uint128_t) x249) * x951;
  uint128_t x957 = ((uint128_t) x252) * x950;
  uint128_t x958 = ((uint128_t) x255) * x949;
  uint128_t x959 = x957 + x958;
  uint128_t x960 = x956 + x959;
  uint128_t x961 = x955 + x960;
  uint8_t x962 = 0b00010011;
  uint128_t x963 = x962 * x961;
  uint128_t x964 = x954 + x963;
  uint8_t x965 = 0b00110011;
  uint64_t x966 = (uint64_t) (x964 >> x965);
  uint128_t x967 = ((uint128_t) x255) * x953;
  uint128_t x968 = ((uint128_t) x258) * x952;
  uint128_t x969 = x967 + x968;
  uint128_t x970 = ((uint128_t) x246) * x951;
  uint128_t x971 = ((uint128_t) x249) * x950;
  uint128_t x972 = ((uint128_t) x252) * x949;
  uint128_t x973 = x971 + x972;
  uint128_t x974 = x970 + x973;
  uint8_t x975 = 0b00010011;
  uint128_t x976 = x975 * x974;
  uint128_t x977 = x969 + x976;
  uint128_t x978 = x966 + x977;
  uint8_t x979 = 0b00110011;
  uint64_t x980 = (uint64_t) (x978 >> x979);
  uint128_t x981 = ((uint128_t) x252) * x953;
  uint128_t x982 = ((uint128_t) x255) * x952;
  uint128_t x983 = ((uint128_t) x258) * x951;
  uint128_t x984 = x982 + x983;
  uint128_t x985 = x981 + x984;
  uint128_t x986 = ((uint128_t) x246) * x950;
  uint128_t x987 = ((uint128_t) x249) * x949;
  uint128_t x988 = x986 + x987;
  uint8_t x989 = 0b00010011;
  uint128_t x990 = x989 * x988;
  uint128_t x991 = x985 + x990;
  uint128_t x992 = x980 + x991;
  uint8_t x993 = 0b00110011;
  uint64_t x994 = (uint64_t) (x992 >> x993);
  uint128_t x995 = ((uint128_t) x249) * x953;
  uint128_t x996 = ((uint128_t) x252) * x952;
  uint128_t x997 = ((uint128_t) x255) * x951;
  uint128_t x998 = ((uint128_t) x258) * x950;
  uint128_t x999 = x997 + x998;
  uint128_t x1000 = x996 + x999;
  uint128_t x1001 = x995 + x1000;
  uint128_t x1002 = ((uint128_t) x246) * x949;
  uint8_t x1003 = 0b00010011;
  uint128_t x1004 = x1003 * x1002;
  uint128_t x1005 = x1001 + x1004;
  uint128_t x1006 = x994 + x1005;
  uint8_t x1007 = 0b00110011;
  uint64_t x1008 = (uint64_t) (x1006 >> x1007);
  uint128_t x1009 = ((uint128_t) x246) * x953;
  uint128_t x1010 = ((uint128_t) x249) * x952;
  uint128_t x1011 = ((uint128_t) x252) * x951;
  uint128_t x1012 = ((uint128_t) x255) * x950;
  uint128_t x1013 = ((uint128_t) x258) * x949;
  uint128_t x1014 = x1012 + x1013;
  uint128_t x1015 = x1011 + x1014;
  uint128_t x1016 = x1010 + x1015;
  uint128_t x1017 = x1009 + x1016;
  uint128_t x1018 = x1008 + x1017;
  uint8_t x1019 = 0b00110011;
  uint64_t x1020 = (uint64_t) (x1018 >> x1019);
  uint8_t x1021 = 0b00010011;
  uint64_t x1022 = x1021 * x1020;
  uint64_t x1023 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x1024 = x964 & x1023;
  uint64_t x1025 = x1022 + x1024;
  uint8_t x1026 = 0b00110011;
  uint16_t x1027 = (uint16_t) (x1025 >> x1026);
  uint64_t x1028 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x1029 = x978 & x1028;
  uint64_t x1030 = x1027 + x1029;
  uint64_t x1031 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x1032 = x1018 & x1031;
  uint64_t x1033 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x1034 = x1006 & x1033;
  uint8_t x1035 = 0b00110011;
  bool x1036 = (bool) (x1030 >> x1035);
  uint64_t x1037 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x1038 = x992 & x1037;
  uint64_t x1039 = x1036 + x1038;
  uint64_t x1040 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x1041 = x1030 & x1040;
  uint64_t x1042 = 0b0000000000000111111111111111111111111111111111111111111111111111;
  uint64_t x1043 = x1025 & x1042;

  x2[4] =  x847, x2[3] =  x849, x2[2] =  x854, x2[1] =  x856, x2[0] =  x858;
  z2[4] = x1032, z2[3] = x1034, z2[2] = x1039, z2[1] = x1041, z2[0] = x1043;
  x3[4] =  x547, x3[3] =  x549, x3[2] =  x554, x3[1] =  x556, x3[0] =  x558;
  z3[4] =  x757, z3[3] =  x759, z3[2] =  x764, z3[1] =  x766, z3[0] =  x768;
}

// -----------------------------------------------------------------------------
// Maybe swap the contents of two limb arrays (@a and @b), each @len elements
// long. Perform the swap iff @swap is non-zero.
//
// This function performs the swap without leaking any side-channel
// information.
// -----------------------------------------------------------------------------
static void
swap_conditional(limb a[5], limb b[5], limb iswap) {
  unsigned i;
  const limb swap = -iswap;

  for (i = 0; i < 5; ++i) {
    const limb x = swap & (a[i] ^ b[i]);
    a[i] ^= x;
    b[i] ^= x;
  }
}

/* Calculates nQ where Q is the x-coordinate of a point on the curve
 *
 *   resultx/resultz: the x coordinate of the resulting curve point (short form)
 *   n: a little endian, 32-byte number
 *   q: a point of the curve (short form)
 */
static void
cmult(limb *resultx, limb *resultz, const u8 *n, const limb *q) {
  limb a[5] = {0}, b[5] = {1}, c[5] = {1}, d[5] = {0};
  limb *nqpqx = a, *nqpqz = b, *nqx = c, *nqz = d, *t;
  limb e[5] = {0}, f[5] = {1}, g[5] = {0}, h[5] = {1};
  limb *nqpqx2 = e, *nqpqz2 = f, *nqx2 = g, *nqz2 = h;

  unsigned i, j;

  memcpy(nqpqx, q, sizeof(limb) * 5);

  for (i = 0; i < 32; ++i) {
    u8 byte = n[31 - i];
    for (j = 0; j < 8; ++j) {
      const limb bit = byte >> 7;

      swap_conditional(nqx, nqpqx, bit);
      swap_conditional(nqz, nqpqz, bit);
      fmonty(nqx2, nqz2,
             nqpqx2, nqpqz2,
             nqx, nqz,
             nqpqx, nqpqz,
             q);
      swap_conditional(nqx2, nqpqx2, bit);
      swap_conditional(nqz2, nqpqz2, bit);

      t = nqx;
      nqx = nqx2;
      nqx2 = t;
      t = nqz;
      nqz = nqz2;
      nqz2 = t;
      t = nqpqx;
      nqpqx = nqpqx2;
      nqpqx2 = t;
      t = nqpqz;
      nqpqz = nqpqz2;
      nqpqz2 = t;

      byte <<= 1;
    }
  }

  memcpy(resultx, nqx, sizeof(limb) * 5);
  memcpy(resultz, nqz, sizeof(limb) * 5);
}


// -----------------------------------------------------------------------------
// Shamelessly copied from djb's code, tightened a little
// -----------------------------------------------------------------------------
static void
crecip(felem out, const felem z) {
  felem a,t0,b,c;

  /* 2 */ fsquare_times(a, z, 1); // a = 2
  /* 8 */ fsquare_times(t0, a, 2);
  /* 9 */ fmul(b, t0, z); // b = 9
  /* 11 */ fmul(a, b, a); // a = 11
  /* 22 */ fsquare_times(t0, a, 1);
  /* 2^5 - 2^0 = 31 */ fmul(b, t0, b);
  /* 2^10 - 2^5 */ fsquare_times(t0, b, 5);
  /* 2^10 - 2^0 */ fmul(b, t0, b);
  /* 2^20 - 2^10 */ fsquare_times(t0, b, 10);
  /* 2^20 - 2^0 */ fmul(c, t0, b);
  /* 2^40 - 2^20 */ fsquare_times(t0, c, 20);
  /* 2^40 - 2^0 */ fmul(t0, t0, c);
  /* 2^50 - 2^10 */ fsquare_times(t0, t0, 10);
  /* 2^50 - 2^0 */ fmul(b, t0, b);
  /* 2^100 - 2^50 */ fsquare_times(t0, b, 50);
  /* 2^100 - 2^0 */ fmul(c, t0, b);
  /* 2^200 - 2^100 */ fsquare_times(t0, c, 100);
  /* 2^200 - 2^0 */ fmul(t0, t0, c);
  /* 2^250 - 2^50 */ fsquare_times(t0, t0, 50);
  /* 2^250 - 2^0 */ fmul(t0, t0, b);
  /* 2^255 - 2^5 */ fsquare_times(t0, t0, 5);
  /* 2^255 - 21 */ fmul(out, t0, a);
}

void
x25519_donna_fiat(u8 *mypublic, const u8 *secret, const u8 *basepoint) {
  limb bp[5], x[5], z[5], zmone[5];
  uint8_t e[32];
  int i;

  for (i = 0;i < 32;++i) e[i] = secret[i];
  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;

  fexpand(bp, basepoint);
  cmult(x, z, e, bp);
  crecip(zmone, z);
  fmul(z, x, zmone);
  fcontract(mypublic, z);
}

#endif
