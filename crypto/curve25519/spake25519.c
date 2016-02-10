/* Copyright (c) 2016, Google Inc.
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

#include <openssl/curve25519.h>

#include <string.h>

#include <openssl/bytestring.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "internal.h"


/* The following precomputation tables are for the following
 * points used in the SPAKE2 protocol.
 *
 * N:
 *   x: 47050762474146528052713103977216919190719173098550108245349760773179710360074
 *   y: 5057061962389490295910433500531660103436368869035587473830813966497215880723
 *   encoded: 131e77a4c7830cecf791ad69e988ba852c8831655d5cdb6173d85f5a15322e0b
 *
 * M:
 *   x: 19625461055630627773638026675621229866897061648918266818389186031720168582749
 *   y: 12784115637457221145469778217612323034857701258071455234302143096577724987265
 *   encoded: 81371741a5c1d38e0ca9e0aec1bc6fcba0ae99fb56e80323942d1a89938d439c
 *
 * These points and their precomputation tables are generated with the
 * following Python code. For a description of the precomputation table,
 * see curve25519.c in this directory.
 *
 * import hashlib
 * import ed25519 as E  # http://ed25519.cr.yp.to/python/ed25519.py
 *
 * SEED_N = 'Ed25519 point generation seed (N)'
 * SEED_M = 'Ed25519 point generation seed (M)'
 *
 * def genpoint(seed):
 *     v = hashlib.sha256(seed).digest()
 *     it = 1
 *     while True:
 *         try:
 *             x,y = E.decodepoint(v)
 *         except Exception, e:
 *             print e
 *             it += 1
 *             v = hashlib.sha256(v).digest()
 *             continue
 *         print "Found in %d iterations:" % it
 *         print "  x = %d" % x
 *         print "  y = %d" % y
 *         print " Encoded (hex)"
 *         print E.encodepoint((x,y)).encode('hex')
 *         return (x,y)
 *
 * def gentable(P):
 *     t = []
 *     for i in range(1,16):
 *         k = (i >> 3 & 1) * (1 << 192) + \
 *             (i >> 2 & 1) * (1 << 128) + \
 *             (i >> 1 & 1) * (1 <<  64) + \
 *             (i      & 1)
 *         t.append(E.scalarmult(P, k))
 *     return ''.join(E.encodeint(x) + E.encodeint(y) for (x,y) in t)
 *
 * def printtable(table, name):
 *     print "static const uint8_t %s[15 * 2 * 32] = {" % name,
 *     for i in range(15 * 2 * 32):
 *         if i % 12 == 0:
 *             print "\n   ",
 *         print " 0x%02x," % ord(table[i]),
 *     print "\n};"
 *
 * if __name__ == "__main__":
 *     print "Searching for N"
 *     N = genpoint(SEED_N)
 *     print "Generating precomputation table for N"
 *     Ntable = gentable(N)
 *     printtable(Ntable, "kSpakeNSmallPrecomp")
 *
 *     print "Searching for M"
 *     M = genpoint(SEED_M)
 *     print "Generating precomputation table for M"
 *     Mtable = gentable(M)
 *     printtable(Mtable, "kSpakeMSmallPrecomp")
 *
 */
static const uint8_t kSpakeNSmallPrecomp[15 * 2 * 32] = {
    0x0a, 0xca, 0xbb, 0x39, 0xef, 0x2d, 0x36, 0xa3, 0xe0, 0xf4, 0x8c, 0x71,
    0x75, 0x27, 0x7c, 0xa9, 0x55, 0x35, 0x34, 0xc6, 0x73, 0x69, 0x08, 0x84,
    0x8d, 0x49, 0xe9, 0xa2, 0xaf, 0xc9, 0x05, 0x68, 0x13, 0x1e, 0x77, 0xa4,
    0xc7, 0x83, 0x0c, 0xec, 0xf7, 0x91, 0xad, 0x69, 0xe9, 0x88, 0xba, 0x85,
    0x2c, 0x88, 0x31, 0x65, 0x5d, 0x5c, 0xdb, 0x61, 0x73, 0xd8, 0x5f, 0x5a,
    0x15, 0x32, 0x2e, 0x0b, 0x3e, 0x48, 0xf5, 0x53, 0x92, 0x45, 0x13, 0xfc,
    0x69, 0x46, 0xb3, 0x6f, 0x67, 0x91, 0x87, 0x2e, 0x2c, 0x02, 0x06, 0x97,
    0x06, 0x17, 0x64, 0x29, 0x34, 0xca, 0x53, 0x90, 0x71, 0x97, 0x99, 0x79,
    0x17, 0x99, 0x46, 0xf8, 0x7f, 0x38, 0x36, 0x08, 0x4d, 0x86, 0x51, 0xe4,
    0x83, 0xbd, 0x59, 0x5e, 0x46, 0x79, 0x69, 0xd1, 0xc3, 0x03, 0x64, 0x9b,
    0xb1, 0xd6, 0x95, 0x09, 0xaa, 0x98, 0x0d, 0x37, 0x86, 0x25, 0xc3, 0xd0,
    0x5b, 0x46, 0xc9, 0xa1, 0xc6, 0x9f, 0x99, 0xed, 0x84, 0x2e, 0x7b, 0x27,
    0x71, 0x43, 0x66, 0x06, 0xca, 0xdc, 0xf1, 0x94, 0xbe, 0x75, 0x48, 0x5a,
    0x3a, 0xaf, 0xc1, 0x72, 0xd9, 0x75, 0x8b, 0xa6, 0x18, 0x7f, 0x04, 0x63,
    0xed, 0x80, 0x79, 0x01, 0x18, 0x76, 0xf7, 0x5f, 0xb7, 0xe1, 0xfb, 0xc5,
    0x2e, 0x7d, 0xa3, 0x3c, 0x28, 0x57, 0x8a, 0xeb, 0x34, 0x4f, 0x42, 0x7b,
    0x4c, 0x68, 0xb1, 0x10, 0xc6, 0x40, 0x3b, 0xaa, 0x21, 0x2d, 0x86, 0x9f,
    0x16, 0x53, 0x1c, 0x71, 0x71, 0x0d, 0x83, 0x29, 0x7a, 0x04, 0x66, 0xf3,
    0x18, 0x02, 0x23, 0x07, 0x6e, 0x48, 0xfa, 0x48, 0x0e, 0xaa, 0x82, 0xe1,
    0x9e, 0x32, 0xe2, 0x37, 0x47, 0x1a, 0xc9, 0x75, 0x1f, 0x49, 0xd2, 0xb4,
    0x07, 0x53, 0xfc, 0x14, 0x33, 0x4d, 0xf3, 0x0a, 0xa2, 0x59, 0xfa, 0x34,
    0x41, 0x36, 0x5f, 0x27, 0xff, 0x70, 0x30, 0x0c, 0x96, 0x61, 0x18, 0xc5,
    0x82, 0x03, 0x70, 0x8e, 0x4b, 0xbe, 0x94, 0x95, 0xb8, 0xa1, 0x66, 0x38,
    0x08, 0x25, 0x85, 0xb0, 0xed, 0x7b, 0x62, 0xa8, 0xa9, 0xd7, 0x5b, 0x25,
    0x43, 0x2e, 0x29, 0x53, 0xc0, 0x55, 0x23, 0xe3, 0x01, 0x10, 0x64, 0x1d,
    0xaf, 0x4b, 0xdd, 0xd4, 0x9f, 0x59, 0xcb, 0xa8, 0x77, 0xac, 0x03, 0xaa,
    0xc4, 0xf9, 0x22, 0x65, 0x91, 0x0b, 0x74, 0x4b, 0x4c, 0x6c, 0x28, 0x91,
    0x71, 0x98, 0x60, 0x6e, 0x23, 0x7f, 0x60, 0x02, 0xc3, 0xd3, 0x5c, 0x5e,
    0x04, 0x8a, 0x2a, 0xfc, 0x1f, 0x2c, 0x74, 0xdc, 0x70, 0x3d, 0x4d, 0x7c,
    0xfb, 0x49, 0xc9, 0x19, 0xb2, 0xcf, 0xc0, 0x46, 0x96, 0xc1, 0xf3, 0xde,
    0xf3, 0x34, 0xcc, 0x64, 0x43, 0xb4, 0xce, 0xeb, 0x77, 0xa3, 0x32, 0x86,
    0xdd, 0x89, 0x50, 0x9a, 0xcd, 0x34, 0xf1, 0x2f, 0x8a, 0x90, 0xc7, 0x70,
    0x94, 0xdb, 0xff, 0x1a, 0xdf, 0xef, 0xeb, 0xcf, 0xa7, 0x0f, 0x07, 0x2e,
    0x6d, 0xe8, 0x41, 0xf9, 0xbf, 0xf3, 0x5e, 0x4b, 0x94, 0x3d, 0xad, 0x09,
    0x9d, 0x60, 0x39, 0x28, 0xa2, 0x26, 0xb0, 0x4f, 0xfb, 0x1c, 0x4b, 0x36,
    0xce, 0x7b, 0xe4, 0xe7, 0xd6, 0x3a, 0x7e, 0x66, 0x98, 0xd8, 0x58, 0xa6,
    0x77, 0x06, 0x92, 0xc1, 0x9a, 0x4a, 0x4f, 0xfa, 0xf8, 0xc5, 0x31, 0x88,
    0x7c, 0x8f, 0x8b, 0x79, 0x01, 0x9e, 0x68, 0xf9, 0x5f, 0x4d, 0x48, 0xc8,
    0x34, 0x42, 0xbd, 0x20, 0xe3, 0x7d, 0xbb, 0xb3, 0x51, 0xeb, 0xff, 0xc2,
    0xe7, 0xbe, 0xca, 0x57, 0xf5, 0x5e, 0x86, 0x46, 0x0f, 0x64, 0x25, 0x01,
    0x63, 0xc1, 0xf2, 0x75, 0xd6, 0x8c, 0x7a, 0xb4, 0x22, 0x8e, 0xc9, 0x34,
    0x31, 0x81, 0x3e, 0x78, 0x8d, 0x2e, 0x1e, 0x0e, 0x4e, 0x8c, 0x05, 0x8d,
    0xc8, 0xb6, 0xc0, 0x16, 0xc4, 0x44, 0x52, 0x05, 0x26, 0xab, 0xc5, 0x84,
    0x28, 0x7c, 0xb0, 0x87, 0x4b, 0xe1, 0xc0, 0xd2, 0x4f, 0x71, 0x41, 0x9e,
    0xb0, 0x60, 0xa4, 0x23, 0xb8, 0xfc, 0xfd, 0xde, 0x09, 0x41, 0xc2, 0xe3,
    0x06, 0x1e, 0xc6, 0x6a, 0xd4, 0xee, 0x0e, 0x40, 0xf3, 0x6b, 0x52, 0xc6,
    0xb1, 0xd0, 0x38, 0x49, 0xe4, 0x13, 0x17, 0x7f, 0x3a, 0x0e, 0xdd, 0x07,
    0x96, 0xdc, 0xf6, 0x4a, 0x9f, 0x14, 0xf7, 0x94, 0xcc, 0xb3, 0xf6, 0x30,
    0x43, 0x09, 0x1b, 0xfc, 0x2c, 0xb0, 0x34, 0x1c, 0x58, 0xb6, 0x54, 0xdf,
    0x46, 0x0c, 0xc3, 0xe0, 0xc8, 0x1d, 0x0e, 0xb7, 0x0d, 0x46, 0xce, 0xe2,
    0x5c, 0x92, 0x43, 0x8c, 0xc8, 0xad, 0x0a, 0x6a, 0xb0, 0x26, 0x97, 0x11,
    0x36, 0xeb, 0x82, 0x23, 0xa7, 0xa6, 0x1f, 0x40, 0xc1, 0x04, 0x7d, 0x13,
    0x5c, 0xac, 0x4c, 0xe4, 0x2e, 0xe2, 0xf0, 0x19, 0x71, 0xc7, 0xc3, 0x39,
    0xd7, 0xa6, 0x96, 0x69, 0xc8, 0xed, 0xa4, 0xb7, 0xfd, 0x7b, 0xef, 0xdc,
    0xa7, 0xe2, 0x37, 0xb8, 0xf2, 0x48, 0xf9, 0xd1, 0x4b, 0x3a, 0xf4, 0xc8,
    0xff, 0xdc, 0x0f, 0x20, 0x12, 0xbb, 0x7e, 0xa4, 0x91, 0x63, 0x70, 0x1c,
    0x65, 0xaf, 0x2a, 0xd6, 0x83, 0xc6, 0x03, 0xfe, 0x33, 0xab, 0xca, 0x91,
    0xdf, 0x8a, 0x48, 0xe7, 0x2f, 0x8c, 0x90, 0xb3, 0x18, 0xb5, 0x3a, 0x30,
    0x13, 0x16, 0xff, 0x69, 0x1a, 0x0e, 0xdb, 0x65, 0x99, 0x82, 0x74, 0x5f,
    0x08, 0x0f, 0x59, 0xe8, 0x22, 0x07, 0x96, 0xb7, 0x58, 0x3b, 0x58, 0xa2,
    0x48, 0x7f, 0x16, 0x71, 0xae, 0xc3, 0x35, 0xee, 0xcf, 0x97, 0x08, 0x4b,
    0x5a, 0xf4, 0xa8, 0x27, 0xb1, 0x13, 0x3c, 0x19, 0x3c, 0x17, 0xdc, 0x23,
    0xf3, 0xc5, 0xb2, 0xdf, 0xed, 0x90, 0x12, 0x43, 0x9d, 0xc4, 0x48, 0x28,
    0xcb, 0x5c, 0xf5, 0x68, 0xdd, 0x4c, 0x60, 0x2d, 0x9e, 0xaf, 0x94, 0x48,
    0x1e, 0xfc, 0x8f, 0x2d, 0x57, 0xd7, 0xd0, 0xd0, 0x10, 0x58, 0xd0, 0x3b,
    0xa5, 0xd5, 0x65, 0x9b, 0x81, 0x30, 0x75, 0x1a, 0x92, 0xd2, 0xf7, 0x91,
    0x9f, 0x48, 0xa7, 0xe3, 0xc7, 0x6f, 0xbd, 0x5a, 0x32, 0x6f, 0x3c, 0x9e,
    0xae, 0xbd, 0xa6, 0xe1, 0xa0, 0x10, 0xff, 0xb7, 0xd7, 0xa7, 0x9f, 0x87,
    0x5b, 0x82, 0xdb, 0xb9, 0xc5, 0x88, 0x1c, 0x6c, 0xdf, 0x6d, 0xb4, 0xcc,
    0xf2, 0x45, 0x33, 0x10, 0xf6, 0x0e, 0xb6, 0xb8, 0xe2, 0xc2, 0xfd, 0x5d,
    0x72, 0x79, 0x71, 0x26, 0xe9, 0xd8, 0x15, 0x8a, 0x88, 0xf8, 0x6e, 0x71,
    0x4e, 0xe3, 0xd7, 0xe5, 0xa2, 0x14, 0x14, 0x6f, 0x6d, 0x1b, 0x9e, 0x17,
    0xc5, 0x41, 0x27, 0x66, 0xcf, 0xe4, 0xac, 0xab, 0x75, 0xa3, 0xc4, 0xa1,
    0x34, 0xdb, 0xd2, 0x10, 0x66, 0x7c, 0x5e, 0x01, 0x48, 0x7a, 0xbb, 0xce,
    0x91, 0x3d, 0x2c, 0x87, 0x17, 0x5d, 0xe5, 0x39, 0xa6, 0x89, 0x6c, 0xc5,
    0x4b, 0x45, 0xf0, 0xe0, 0x01, 0xd7, 0x36, 0xc8, 0x00, 0xc7, 0xa9, 0x38,
    0x37, 0xc9, 0xd8, 0x7d, 0x9e, 0x5b, 0xf6, 0x63, 0x50, 0x32, 0x63, 0xb1,
    0x9c, 0xe7, 0x40, 0x04, 0xb6, 0xec, 0xab, 0x09, 0x58, 0x1e, 0x94, 0x78,
    0xf0, 0x81, 0x2a, 0x0f, 0x4d, 0xeb, 0xc4, 0xd4, 0xd4, 0xc9, 0xe9, 0x47,
    0xb6, 0xd3, 0x66, 0x4b, 0x25, 0x71, 0x29, 0xcf, 0xc9, 0x81, 0xf2, 0x40,
};

static const uint8_t kSpakeMSmallPrecomp[15 * 2 * 32] = {
    0x5d, 0x6e, 0xce, 0x15, 0xd1, 0x87, 0x32, 0x35, 0xea, 0x32, 0x84, 0x2e,
    0xfa, 0x01, 0x23, 0xab, 0xfe, 0x14, 0xde, 0xfd, 0xa3, 0xfa, 0x9e, 0x75,
    0xa7, 0xe0, 0x82, 0x93, 0x08, 0x9e, 0x63, 0x2b, 0x81, 0x37, 0x17, 0x41,
    0xa5, 0xc1, 0xd3, 0x8e, 0x0c, 0xa9, 0xe0, 0xae, 0xc1, 0xbc, 0x6f, 0xcb,
    0xa0, 0xae, 0x99, 0xfb, 0x56, 0xe8, 0x03, 0x23, 0x94, 0x2d, 0x1a, 0x89,
    0x93, 0x8d, 0x43, 0x1c, 0xed, 0x74, 0x50, 0x3f, 0x4c, 0x9a, 0x9e, 0xb9,
    0xc3, 0x92, 0x5b, 0x49, 0xc4, 0x0e, 0x00, 0x8d, 0x91, 0xd1, 0x59, 0xff,
    0x27, 0x92, 0xd4, 0x0d, 0x7b, 0xa7, 0x9d, 0x03, 0xb7, 0xfa, 0xc7, 0x0b,
    0xa1, 0xc1, 0xcc, 0x62, 0x0d, 0xd6, 0xcc, 0x0c, 0x50, 0xfa, 0xf2, 0x5b,
    0xf9, 0x46, 0x52, 0xbe, 0xaa, 0x84, 0x4f, 0x9b, 0xea, 0xb7, 0x95, 0xe8,
    0xf3, 0x8e, 0xc2, 0xa5, 0x22, 0x88, 0xaf, 0x13, 0xc1, 0xde, 0x5a, 0xfe,
    0x83, 0x35, 0xdc, 0xfb, 0x40, 0xdf, 0x85, 0xb3, 0x45, 0x51, 0x3b, 0xb8,
    0xff, 0xce, 0xc5, 0x2a, 0x9f, 0x30, 0xac, 0x47, 0x07, 0xb8, 0x83, 0x07,
    0xb6, 0x2f, 0x7b, 0x30, 0xdf, 0x1b, 0x48, 0x98, 0x6b, 0x80, 0xc8, 0x8a,
    0x00, 0x03, 0xb1, 0x50, 0x5b, 0xa2, 0x78, 0x44, 0x6a, 0xf5, 0x06, 0x35,
    0x9f, 0xb9, 0x69, 0xc8, 0x95, 0xc1, 0x8c, 0x6c, 0xe1, 0xa6, 0xc0, 0x14,
    0xe6, 0x47, 0xcb, 0xdf, 0x3d, 0x7a, 0x41, 0x14, 0x4b, 0x59, 0xd7, 0x98,
    0x3b, 0xe3, 0x87, 0x05, 0xd7, 0x18, 0x59, 0x26, 0x1a, 0xc2, 0x38, 0xac,
    0x59, 0x76, 0x7c, 0xf0, 0xc6, 0x6e, 0xac, 0x13, 0xa6, 0x91, 0x65, 0x0c,
    0xf4, 0x7f, 0x16, 0xb8, 0x85, 0x90, 0xe6, 0x0a, 0xa8, 0x10, 0x4c, 0x52,
    0x71, 0xc8, 0xa7, 0xe4, 0xff, 0x44, 0xc8, 0x2f, 0x92, 0x70, 0x29, 0x2f,
    0xc5, 0x61, 0xcb, 0x4f, 0x6e, 0xd5, 0x6d, 0xe3, 0xdf, 0x17, 0xb2, 0x64,
    0x79, 0x6d, 0x22, 0xa2, 0xae, 0x9e, 0x2a, 0xef, 0x5c, 0xcb, 0xb8, 0xaa,
    0xb6, 0x49, 0x51, 0x95, 0xf4, 0x4b, 0xd1, 0x99, 0xad, 0xe7, 0x00, 0x32,
    0x79, 0x5d, 0x56, 0x32, 0x4e, 0xa9, 0x59, 0x7a, 0xa0, 0x46, 0xa0, 0xbc,
    0xab, 0x4c, 0x2c, 0xc4, 0x67, 0x83, 0x2c, 0xd2, 0x6c, 0x00, 0x1b, 0x8c,
    0xe7, 0x86, 0xcf, 0xde, 0xcb, 0xb1, 0xd1, 0x07, 0x91, 0xf6, 0x37, 0x4d,
    0x1c, 0xc8, 0x83, 0x58, 0x55, 0x75, 0x69, 0x83, 0xbe, 0x14, 0x49, 0x62,
    0x38, 0x9c, 0xac, 0x38, 0x36, 0x29, 0x9b, 0x68, 0xf3, 0x43, 0xea, 0xad,
    0xaa, 0xca, 0x08, 0x44, 0x70, 0x66, 0xbf, 0x25, 0xa2, 0xbb, 0x3f, 0x0a,
    0x70, 0xb2, 0xd6, 0x46, 0x85, 0x18, 0xd5, 0x65, 0xde, 0xb4, 0x04, 0x85,
    0xee, 0x98, 0x46, 0x12, 0x84, 0xde, 0x38, 0x3b, 0x21, 0xb1, 0x71, 0x5e,
    0x5e, 0x23, 0xc4, 0xbc, 0x5c, 0x34, 0x5f, 0x29, 0xb3, 0xe8, 0xf6, 0x46,
    0x1b, 0x49, 0xf0, 0x16, 0x9d, 0x5a, 0x60, 0x04, 0x8e, 0x89, 0x4f, 0x9e,
    0x3e, 0x5f, 0x93, 0xef, 0xe7, 0x49, 0x81, 0x2e, 0x75, 0x5c, 0x6d, 0x81,
    0xb9, 0x07, 0x54, 0xe9, 0xcd, 0x8c, 0x88, 0x4a, 0xdc, 0x45, 0x01, 0x7f,
    0xcd, 0x79, 0x6b, 0x6f, 0x42, 0xa0, 0x77, 0xcd, 0x00, 0x2a, 0xb4, 0x49,
    0x6f, 0x0c, 0x13, 0x07, 0x97, 0x97, 0xc4, 0x30, 0x85, 0x70, 0xc1, 0x10,
    0xe6, 0x4b, 0xcc, 0x06, 0xe3, 0x98, 0xf1, 0x45, 0x76, 0x8c, 0xca, 0x00,
    0x94, 0x65, 0x99, 0xdb, 0x9d, 0x21, 0xc2, 0xd7, 0xfe, 0xfd, 0xb5, 0x29,
    0xe0, 0xd5, 0x53, 0x24, 0xa6, 0xdd, 0x68, 0xd6, 0x4a, 0xb6, 0x92, 0xb2,
    0x24, 0xf1, 0x42, 0xbd, 0x3f, 0x42, 0xfa, 0x1f, 0x46, 0xff, 0x39, 0x47,
    0x3b, 0xbe, 0xc0, 0x6f, 0x80, 0xcf, 0xe2, 0x14, 0x74, 0x36, 0xb8, 0x78,
    0xbd, 0xb7, 0x93, 0x3b, 0x1c, 0x86, 0x0a, 0x90, 0xaf, 0x34, 0x65, 0x04,
    0x8e, 0xbc, 0x0f, 0x40, 0x8e, 0xee, 0x40, 0x71, 0x71, 0xc6, 0x19, 0x98,
    0xdd, 0x84, 0x0b, 0x48, 0x46, 0x74, 0xbd, 0x2b, 0xa5, 0xc6, 0x2f, 0xeb,
    0xcb, 0x4f, 0x16, 0xf6, 0x8c, 0x66, 0xbc, 0x58, 0xd9, 0x19, 0x92, 0x26,
    0xe8, 0x51, 0x74, 0x22, 0xc9, 0x58, 0x60, 0xbd, 0x9e, 0xad, 0x54, 0x2d,
    0xa0, 0xe0, 0x5b, 0x70, 0x00, 0xca, 0xd1, 0xd5, 0x92, 0xba, 0xfc, 0x0f,
    0x02, 0x1a, 0x50, 0x43, 0xf7, 0x08, 0xb9, 0x06, 0xa6, 0x12, 0x49, 0xdf,
    0x5e, 0x61, 0xfe, 0x80, 0x0e, 0xdf, 0x19, 0x0b, 0x36, 0xe1, 0x95, 0x4a,
    0x1a, 0x88, 0x6a, 0x49, 0x0f, 0x2e, 0xe1, 0x2f, 0x14, 0x9f, 0x12, 0xc8,
    0x57, 0x9d, 0xcb, 0xec, 0xdd, 0x70, 0x99, 0x21, 0x99, 0x3e, 0xa5, 0x7e,
    0xcf, 0xf1, 0x06, 0x2c, 0x98, 0xc8, 0x33, 0xb1, 0xd0, 0x0e, 0x48, 0xbd,
    0x30, 0x24, 0x68, 0xbd, 0xac, 0x91, 0xd6, 0xf8, 0x7e, 0x7a, 0xce, 0x98,
    0xb9, 0x87, 0x7a, 0xf7, 0x3e, 0x3b, 0x16, 0x57, 0x7d, 0x3c, 0xe8, 0x63,
    0xe6, 0x7b, 0x22, 0x93, 0xff, 0x68, 0xc5, 0x15, 0x0e, 0xc0, 0x7a, 0x34,
    0x08, 0xf3, 0xf8, 0x39, 0x4c, 0xf4, 0x58, 0xe5, 0x17, 0xd5, 0xc9, 0x1a,
    0x14, 0xf1, 0x00, 0xe0, 0x8d, 0x3e, 0x6b, 0x2d, 0x24, 0x23, 0x3a, 0xa8,
    0xa3, 0x83, 0x9d, 0x22, 0xd5, 0xd5, 0xcf, 0xfa, 0x80, 0x04, 0x29, 0xfe,
    0xa1, 0xe5, 0xc7, 0xf4, 0x7b, 0x73, 0x0e, 0xda, 0x5e, 0x5f, 0x4f, 0x4b,
    0xc7, 0xfc, 0xd0, 0x02, 0x53, 0x62, 0xfe, 0x52, 0x91, 0x6e, 0x4c, 0x11,
    0x43, 0xd9, 0xb3, 0x52, 0xe4, 0x8e, 0xf4, 0xca, 0xc0, 0x3a, 0x22, 0x3a,
    0x62, 0x45, 0x8a, 0x9a, 0x6d, 0xe8, 0x1c, 0x77, 0xbb, 0x63, 0x83, 0x5f,
    0xf8, 0xcb, 0x3d, 0x4f, 0x03, 0x40, 0xd3, 0x4e, 0xd1, 0xe6, 0x99, 0x3b,
    0xe3, 0x44, 0xac, 0x1d, 0xd7, 0x8b, 0xb9, 0x87, 0x6b, 0xca, 0xf0, 0x7f,
    0x3f, 0x31, 0xa3, 0x36, 0x3e, 0xf0, 0xea, 0x39, 0xbb, 0x57, 0xb6, 0x8d,
    0xd6, 0x70, 0xad, 0xf3, 0x22, 0x6d, 0x9a, 0x92, 0xac, 0xec, 0x19, 0xfd,
    0xf6, 0xd6, 0xe3, 0x23, 0x32, 0x75, 0xe1, 0x97, 0x86, 0x26, 0xdd, 0xeb,
    0xa3, 0x11, 0x22, 0x65, 0xde, 0xd1, 0xb4, 0xe8, 0x42, 0xbb, 0x49, 0x95,
    0x59, 0x22, 0xf7, 0x15, 0x94, 0x60, 0x81, 0x2b, 0x04, 0xd1, 0x82, 0xc5,
    0xaf, 0x82, 0xe1, 0x19, 0x7e, 0xcc, 0xd4, 0xa6, 0xad, 0x41, 0x14, 0x58,
    0x00, 0x47, 0xa8, 0x57, 0x30, 0x65, 0x89, 0xbb, 0x4d, 0xdb, 0xdc, 0x27,
    0xb9, 0x4b, 0xcf, 0x9d, 0xcc, 0x40, 0x3a, 0xff, 0x8e, 0x11, 0x8f, 0xfd,
    0xab, 0x49, 0xc0, 0xf2, 0xa4, 0x24, 0xa1, 0x70, 0xb0, 0x86, 0x57, 0x89,
    0xc0, 0xe5, 0x11, 0xff, 0x47, 0x68, 0x74, 0x45, 0xc6, 0x61, 0x1c, 0x04,
    0xae, 0x30, 0x89, 0x5a, 0x9c, 0x8e, 0xc2, 0xfc, 0xd0, 0xdc, 0x80, 0x7c,
    0x62, 0x71, 0x14, 0x46, 0xfc, 0x98, 0x80, 0x95, 0x38, 0xe4, 0x56, 0x5b,
    0x72, 0xa7, 0xd9, 0xec, 0xe9, 0x53, 0x06, 0x9e, 0x55, 0x61, 0x01, 0x51,
    0x12, 0xe9, 0x65, 0x02, 0xf3, 0x04, 0xf3, 0x31, 0x91, 0x3f, 0x79, 0x46,
};

enum spake2_state_t {
  spake2_state_init = 0,
  spake2_state_msg_generated,
  spake2_state_key_generated,
};

struct spake2_ctx_st {
  uint8_t private_key[32];
  uint8_t my_msg[32];
  uint8_t password_scalar[32];
  uint8_t *my_name;
  size_t my_name_len;
  uint8_t *their_name;
  size_t their_name_len;
  enum spake2_role_t my_role;
  enum spake2_state_t state;
};

SPAKE2_CTX *SPAKE2_CTX_new(enum spake2_role_t my_role,
                           const uint8_t *my_name, size_t my_name_len,
                           const uint8_t *their_name, size_t their_name_len) {
  SPAKE2_CTX *ctx = OPENSSL_malloc(sizeof(SPAKE2_CTX));
  if (ctx == NULL) {
    return NULL;
  }

  memset(ctx, 0, sizeof(SPAKE2_CTX));
  ctx->my_role = my_role;

  CBS my_name_cbs, their_name_cbs;
  CBS_init(&my_name_cbs, my_name, my_name_len);
  CBS_init(&their_name_cbs, their_name, their_name_len);
  if (!CBS_stow(&my_name_cbs, &ctx->my_name, &ctx->my_name_len) ||
      !CBS_stow(&their_name_cbs, &ctx->their_name, &ctx->their_name_len)) {
    SPAKE2_CTX_free(ctx);
    return NULL;
  }

  return ctx;
}

void SPAKE2_CTX_free(SPAKE2_CTX *ctx) {
  if (ctx == NULL) {
    return;
  }

  OPENSSL_free(ctx->my_name);
  OPENSSL_free(ctx->their_name);
  OPENSSL_free(ctx);
}

/* left_shift_3 sets |n| to |n|*8, where |n| is represented in little-endian
 * order. */
static void left_shift_3(uint8_t n[32]) {
  uint8_t carry = 0;
  unsigned i;

  for (i = 0; i < 32; i++) {
    const uint8_t next_carry = n[i] >> 5;
    n[i] = (n[i] << 3) | carry;
    carry = next_carry;
  }
}

int SPAKE2_generate_msg(SPAKE2_CTX *ctx, uint8_t *out, size_t *out_len,
                         size_t max_out_len, const uint8_t *password,
                         size_t password_len) {
  if (ctx->state != spake2_state_init) {
    return 0;
  }

  if (max_out_len < sizeof(ctx->my_msg)) {
    return 0;
  }

  uint8_t private_tmp[64];
  RAND_bytes(private_tmp, sizeof(private_tmp));
  sc_reduce(private_tmp);
  /* Multiply by the cofactor (eight) so that we'll clear it when operating on
   * the peer's point later in the protocol. */
  left_shift_3(private_tmp);
  memcpy(ctx->private_key, private_tmp, sizeof(ctx->private_key));

  ge_p3 P;
  ge_scalarmult_base(&P, ctx->private_key);

  /* mask = h(password) * <N or M>. */
  uint8_t password_tmp[SHA512_DIGEST_LENGTH];
  SHA512(password, password_len, password_tmp);
  sc_reduce(password_tmp);
  memcpy(ctx->password_scalar, password_tmp, sizeof(ctx->password_scalar));

  ge_p3 mask;
  ge_scalarmult_small_precomp(&mask, ctx->password_scalar,
                              ctx->my_role == spake2_role_alice
                                  ? kSpakeMSmallPrecomp
                                  : kSpakeNSmallPrecomp);

  /* P* = P + mask. */
  ge_cached mask_cached;
  ge_p3_to_cached(&mask_cached, &mask);
  ge_p1p1 Pstar;
  ge_add(&Pstar, &P, &mask_cached);

  /* Encode P* */
  ge_p2 Pstar_proj;
  ge_p1p1_to_p2(&Pstar_proj, &Pstar);
  ge_tobytes(ctx->my_msg, &Pstar_proj);

  memcpy(out, ctx->my_msg, sizeof(ctx->my_msg));
  *out_len = sizeof(ctx->my_msg);
  ctx->state = spake2_state_msg_generated;

  return 1;
}

static void update_with_length_prefix(SHA512_CTX *sha, const uint8_t *data,
                                      const size_t len) {
  uint8_t len_be[8];
  size_t l = len;
  unsigned i;

  for (i = 0; i < 8; i++) {
    len_be[7-i] = l & 0xff;
    l >>= 8;
  }

  SHA512_Update(sha, len_be, sizeof(len_be));
  SHA512_Update(sha, data, len);
}

int SPAKE2_process_msg(SPAKE2_CTX *ctx, uint8_t *out_key, size_t *out_key_len,
                       size_t max_out_key, const uint8_t *their_msg,
                       size_t their_msg_len) {
  if (ctx->state != spake2_state_msg_generated ||
      their_msg_len != 32) {
    return 0;
  }

  ge_p3 Qstar;
  if (0 != ge_frombytes_vartime(&Qstar, their_msg)) {
    /* Point received from peer was not on the curve. */
    return 0;
  }

  /* Unmask peer's value. */
  ge_p3 peers_mask;
  ge_scalarmult_small_precomp(&peers_mask, ctx->password_scalar,
                              ctx->my_role == spake2_role_alice
                                  ? kSpakeNSmallPrecomp
                                  : kSpakeMSmallPrecomp);

  ge_cached peers_mask_cached;
  ge_p3_to_cached(&peers_mask_cached, &peers_mask);

  ge_p1p1 Q_compl;
  ge_p3 Q_ext;
  ge_sub(&Q_compl, &Qstar, &peers_mask_cached);
  ge_p1p1_to_p3(&Q_ext, &Q_compl);

  ge_p2 dh_shared;
  ge_scalarmult(&dh_shared, ctx->private_key, &Q_ext);

  uint8_t dh_shared_encoded[32];
  ge_tobytes(dh_shared_encoded, &dh_shared);

  SHA512_CTX sha;
  SHA512_Init(&sha);
  if (ctx->my_role == spake2_role_alice) {
    update_with_length_prefix(&sha, ctx->my_name, ctx->my_name_len);
    update_with_length_prefix(&sha, ctx->their_name, ctx->their_name_len);
    update_with_length_prefix(&sha, ctx->my_msg, sizeof(ctx->my_msg));
    update_with_length_prefix(&sha, their_msg, 32);
  } else {
    update_with_length_prefix(&sha, ctx->their_name, ctx->their_name_len);
    update_with_length_prefix(&sha, ctx->my_name, ctx->my_name_len);
    update_with_length_prefix(&sha, their_msg, 32);
    update_with_length_prefix(&sha, ctx->my_msg, sizeof(ctx->my_msg));
  }
  /* The password itself is not included, in keeping with the draft but in
   * contrast with the original paper. */
  update_with_length_prefix(&sha, dh_shared_encoded, sizeof(dh_shared_encoded));

  uint8_t key[SHA512_DIGEST_LENGTH];
  SHA512_Final(key, &sha);

  size_t to_copy = max_out_key;
  if (to_copy > sizeof(key)) {
    to_copy = sizeof(key);
  }
  memcpy(out_key, key, to_copy);
  *out_key_len = to_copy;
  ctx->state = spake2_state_key_generated;

  return 1;
}
