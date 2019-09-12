/* Copyright (c) 2017, Google Inc.
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

#include <openssl/crypto.h>

#include <stdio.h>
#include <stdlib.h>

#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/des.h>
#include <openssl/ecdsa.h>
#include <openssl/ec_key.h>
#include <openssl/nid.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "../../internal.h"
#include "../ec/internal.h"
#include "../rand/internal.h"


// MSVC wants to put a NUL byte at the end of non-char arrays and so cannot
// compile this.
#if !defined(_MSC_VER)

#if defined(BORINGSSL_FIPS) && defined(OPENSSL_ANDROID)
// FIPS builds on Android will attempt to write flag files to
// /dev/boringssl/selftest/ named after the module hash. If the flag file
// exists, it's assumed that self-tests have already passed and thus do not need
// to be repeated.  No flag file will be created unless the environment
// variable specified in |kFlagVariable| is set to any value, in order to limit
// creations to specific binaries in accordance with Android's SELinux policies.
#define BORINGSSL_FIPS_SELF_TEST_FLAG_FILE
static const char kFlagPrefix[] = "/dev/boringssl/selftest/";
static const char kFlagVariable[] = "BORINGSSL_SELF_TEST_CREATE_FLAG";
#endif

static void hexdump(const uint8_t *in, size_t len) {
  for (size_t i = 0; i < len; i++) {
    fprintf(stderr, "%02x", in[i]);
  }
}

static int check_test(const void *expected, const void *actual,
                      size_t expected_len, const char *name) {
  if (OPENSSL_memcmp(actual, expected, expected_len) != 0) {
    fprintf(stderr, "%s failed.\nExpected: ", name);
    hexdump(expected, expected_len);
    fprintf(stderr, "\nCalculated: ");
    hexdump(actual, expected_len);
    fprintf(stderr, "\n");
    fflush(stderr);
    return 0;
  }
  return 1;
}

static int set_bignum(BIGNUM **out, const uint8_t *in, size_t len) {
  *out = BN_bin2bn(in, len, NULL);
  return *out != NULL;
}

static RSA *self_test_rsa_key(void) {
  static const uint8_t kN[] = {
      0xd3, 0x3a, 0x62, 0x9f, 0x07, 0x77, 0xb0, 0x18, 0xf3, 0xff, 0xfe, 0xcc,
      0xc9, 0xa2, 0xc2, 0x3a, 0xa6, 0x1d, 0xd8, 0xf0, 0x26, 0x5b, 0x38, 0x90,
      0x17, 0x48, 0x15, 0xce, 0x21, 0xcd, 0xd6, 0x62, 0x99, 0xe2, 0xd7, 0xda,
      0x40, 0x80, 0x3c, 0xad, 0x18, 0xb7, 0x26, 0xe9, 0x30, 0x8a, 0x23, 0x3f,
      0x68, 0x9a, 0x9c, 0x31, 0x34, 0x91, 0x99, 0x06, 0x11, 0x36, 0xb2, 0x9e,
      0x3a, 0xd0, 0xbc, 0xb9, 0x93, 0x4e, 0xb8, 0x72, 0xa1, 0x9f, 0xb6, 0x8c,
      0xd5, 0x17, 0x1f, 0x7e, 0xaa, 0x75, 0xbb, 0xdf, 0xa1, 0x70, 0x48, 0xc4,
      0xec, 0x9a, 0x51, 0xed, 0x41, 0xc9, 0x74, 0xc0, 0x3e, 0x1e, 0x85, 0x2f,
      0xbe, 0x34, 0xc7, 0x65, 0x34, 0x8b, 0x4d, 0x55, 0x4b, 0xe1, 0x45, 0x54,
      0x0d, 0x75, 0x7e, 0x89, 0x4d, 0x0c, 0xf6, 0x33, 0xe5, 0xfc, 0xfb, 0x56,
      0x1b, 0xf2, 0x39, 0x9d, 0xe0, 0xff, 0x55, 0xcf, 0x02, 0x05, 0xb9, 0x74,
      0xd2, 0x91, 0xfc, 0x87, 0xe1, 0xbb, 0x97, 0x2a, 0xe4, 0xdd, 0x20, 0xc0,
      0x38, 0x47, 0xc0, 0x76, 0x3f, 0xa1, 0x9b, 0x5c, 0x20, 0xff, 0xff, 0xc7,
      0x49, 0x3b, 0x4c, 0xaf, 0x99, 0xa6, 0x3e, 0x82, 0x5c, 0x58, 0x27, 0xce,
      0x01, 0x03, 0xc3, 0x16, 0x35, 0x20, 0xe9, 0xf0, 0x15, 0x7a, 0x41, 0xd5,
      0x1f, 0x52, 0xea, 0xdf, 0xad, 0x4c, 0xbb, 0x0d, 0xcb, 0x04, 0x91, 0xb0,
      0x95, 0xa8, 0xce, 0x25, 0xfd, 0xd2, 0x62, 0x47, 0x77, 0xee, 0x13, 0xf1,
      0x48, 0x72, 0x9e, 0xd9, 0x2d, 0xe6, 0x5f, 0xa4, 0xc6, 0x9e, 0x5a, 0xb2,
      0xc6, 0xa2, 0xf7, 0x0a, 0x16, 0x17, 0xae, 0x6b, 0x1c, 0x30, 0x7c, 0x63,
      0x08, 0x83, 0xe7, 0x43, 0xec, 0x54, 0x5e, 0x2c, 0x08, 0x0b, 0x5e, 0x46,
      0xa7, 0x10, 0x93, 0x43, 0x53, 0x4e, 0xe3, 0x16, 0x73, 0x55, 0xce, 0xf2,
      0x94, 0xc0, 0xbe, 0xb3,
  };
  static const uint8_t kE[] = {0x01, 0x00, 0x01};  // 65537
  static const uint8_t kD[] = {
      0x2f, 0x2c, 0x1e, 0xd2, 0x3d, 0x2c, 0xb1, 0x9b, 0x21, 0x02, 0xce, 0xb8,
      0x95, 0x5f, 0x4f, 0xd9, 0x21, 0x38, 0x11, 0x36, 0xb0, 0x9a, 0x36, 0xab,
      0x97, 0x47, 0x75, 0xf7, 0x2e, 0xfd, 0x75, 0x1f, 0x58, 0x16, 0x9c, 0xf6,
      0x14, 0xe9, 0x8e, 0xa3, 0x69, 0x9d, 0x9d, 0x86, 0xfe, 0x5c, 0x1b, 0x3b,
      0x11, 0xf5, 0x55, 0x64, 0x77, 0xc4, 0xfc, 0x53, 0xaa, 0x8c, 0x78, 0x9f,
      0x75, 0xab, 0x20, 0x3a, 0xa1, 0x77, 0x37, 0x22, 0x02, 0x8e, 0x54, 0x8a,
      0x67, 0x1c, 0x5e, 0xe0, 0x3e, 0xd9, 0x44, 0x37, 0xd1, 0x29, 0xee, 0x56,
      0x6c, 0x30, 0x9a, 0x93, 0x4d, 0xd9, 0xdb, 0xc5, 0x03, 0x1a, 0x75, 0xcc,
      0x0f, 0xc2, 0x61, 0xb5, 0x6c, 0x62, 0x9f, 0xc6, 0xa8, 0xc7, 0x8a, 0x60,
      0x17, 0x11, 0x62, 0x4c, 0xef, 0x74, 0x31, 0x97, 0xad, 0x89, 0x2d, 0xe8,
      0x31, 0x1d, 0x8b, 0x58, 0x82, 0xe3, 0x03, 0x1a, 0x6b, 0xdf, 0x3f, 0x3e,
      0xa4, 0x27, 0x19, 0xef, 0x46, 0x7a, 0x90, 0xdf, 0xa7, 0xe7, 0xc9, 0x66,
      0xab, 0x41, 0x1d, 0x65, 0x78, 0x1c, 0x18, 0x40, 0x5c, 0xd6, 0x87, 0xb5,
      0xea, 0x29, 0x44, 0xb3, 0xf5, 0xb3, 0xd2, 0x4f, 0xce, 0x88, 0x78, 0x49,
      0x27, 0x4e, 0x0b, 0x30, 0x85, 0xfb, 0x73, 0xfd, 0x8b, 0x32, 0x15, 0xee,
      0x1f, 0xc9, 0x0e, 0x89, 0xb9, 0x43, 0x2f, 0xe9, 0x60, 0x8d, 0xda, 0xae,
      0x2b, 0x30, 0x99, 0xee, 0x88, 0x81, 0x20, 0x7b, 0x4a, 0xc3, 0x18, 0xf2,
      0x94, 0x02, 0x79, 0x94, 0xaa, 0x65, 0xd9, 0x1b, 0x45, 0x2a, 0xac, 0x6e,
      0x30, 0x48, 0x57, 0xea, 0xbe, 0x79, 0x7d, 0xfc, 0x67, 0xaa, 0x47, 0xc0,
      0xf7, 0x52, 0xfd, 0x0b, 0x63, 0x4e, 0x3d, 0x2e, 0xcc, 0x36, 0xa0, 0xdb,
      0x92, 0x0b, 0xa9, 0x1b, 0xeb, 0xc2, 0xd5, 0x08, 0xd3, 0x85, 0x87, 0xf8,
      0x5d, 0x1a, 0xf6, 0xc1,
  };
  static const uint8_t kP[] = {
      0xf7, 0x06, 0xa3, 0x98, 0x8a, 0x52, 0xf8, 0x63, 0x68, 0x27, 0x4f, 0x68,
      0x7f, 0x34, 0xec, 0x8e, 0x5d, 0xf8, 0x30, 0x92, 0xb3, 0x62, 0x4c, 0xeb,
      0xdb, 0x19, 0x6b, 0x09, 0xc5, 0xa3, 0xf0, 0xbb, 0xff, 0x0f, 0xc2, 0xd4,
      0x9b, 0xc9, 0x54, 0x4f, 0xb9, 0xf9, 0xe1, 0x4c, 0xf0, 0xe3, 0x4c, 0x90,
      0xda, 0x7a, 0x01, 0xc2, 0x9f, 0xc4, 0xc8, 0x8e, 0xb1, 0x1e, 0x93, 0x75,
      0x75, 0xc6, 0x13, 0x25, 0xc3, 0xee, 0x3b, 0xcc, 0xb8, 0x72, 0x6c, 0x49,
      0xb0, 0x09, 0xfb, 0xab, 0x44, 0xeb, 0x4d, 0x40, 0xf0, 0x61, 0x6b, 0xe5,
      0xe6, 0xfe, 0x3e, 0x0a, 0x77, 0x26, 0x39, 0x76, 0x3d, 0x4c, 0x3e, 0x9b,
      0x5b, 0xc0, 0xaf, 0xa2, 0x58, 0x76, 0xb0, 0xe9, 0xda, 0x7f, 0x0e, 0x78,
      0xc9, 0x76, 0x49, 0x5c, 0xfa, 0xb3, 0xb0, 0x15, 0x4b, 0x41, 0xc7, 0x27,
      0xa4, 0x75, 0x28, 0x5c, 0x30, 0x69, 0x50, 0x29,
  };
  static const uint8_t kQ[] = {
      0xda, 0xe6, 0xd2, 0xbb, 0x44, 0xff, 0x4f, 0xdf, 0x57, 0xc1, 0x11, 0xa3,
      0x51, 0xba, 0x17, 0x89, 0x4c, 0x01, 0xc0, 0x0c, 0x97, 0x34, 0x50, 0xcf,
      0x32, 0x1e, 0xc0, 0xbd, 0x7b, 0x35, 0xb5, 0x6a, 0x26, 0xcc, 0xea, 0x4c,
      0x8e, 0x87, 0x4a, 0x67, 0x8b, 0xd3, 0xe5, 0x4f, 0x3a, 0x60, 0x48, 0x59,
      0x04, 0x93, 0x39, 0xd7, 0x7c, 0xfb, 0x19, 0x1a, 0x34, 0xd5, 0xe8, 0xaf,
      0xe7, 0x22, 0x2c, 0x0d, 0xc2, 0x91, 0x69, 0xb6, 0xe9, 0x2a, 0xe9, 0x1c,
      0x4c, 0x6e, 0x8f, 0x40, 0xf5, 0xa8, 0x3e, 0x82, 0x69, 0x69, 0xbe, 0x9f,
      0x7d, 0x5c, 0x7f, 0x92, 0x78, 0x17, 0xa3, 0x6d, 0x41, 0x2d, 0x72, 0xed,
      0x3f, 0x71, 0xfa, 0x97, 0xb4, 0x63, 0xe4, 0x4f, 0xd9, 0x46, 0x03, 0xfb,
      0x00, 0xeb, 0x30, 0x70, 0xb9, 0x51, 0xd9, 0x0a, 0xd2, 0xf8, 0x50, 0xd4,
      0xfb, 0x43, 0x84, 0xf8, 0xac, 0x58, 0xc3, 0x7b,
  };
  static const uint8_t kDModPMinusOne[] = {
      0xf5, 0x50, 0x8f, 0x88, 0x7d, 0xdd, 0xb5, 0xb4, 0x2a, 0x8b, 0xd7, 0x4d,
      0x23, 0xfe, 0xaf, 0xe9, 0x16, 0x22, 0xd2, 0x41, 0xed, 0x88, 0xf2, 0x70,
      0xcb, 0x4d, 0xeb, 0xc1, 0x71, 0x97, 0xc4, 0x0b, 0x3e, 0x5a, 0x2d, 0x96,
      0xab, 0xfa, 0xfd, 0x12, 0x8b, 0xd3, 0x3e, 0x4e, 0x05, 0x6f, 0x04, 0xeb,
      0x59, 0x3c, 0x0e, 0xa1, 0x73, 0xbe, 0x9d, 0x99, 0x2f, 0x05, 0xf9, 0x54,
      0x8d, 0x98, 0x1e, 0x0d, 0xc4, 0x0c, 0xc3, 0x30, 0x23, 0xff, 0xe5, 0xd0,
      0x2b, 0xd5, 0x4e, 0x2b, 0xa0, 0xae, 0xb8, 0x32, 0x84, 0x45, 0x8b, 0x3c,
      0x6d, 0xf0, 0x10, 0x36, 0x9e, 0x6a, 0xc4, 0x67, 0xca, 0xa9, 0xfc, 0x06,
      0x96, 0xd0, 0xbc, 0xda, 0xd1, 0x55, 0x55, 0x8d, 0x77, 0x21, 0xf4, 0x82,
      0x39, 0x37, 0x91, 0xd5, 0x97, 0x56, 0x78, 0xc8, 0x3c, 0xcb, 0x5e, 0xf6,
      0xdc, 0x58, 0x48, 0xb3, 0x7c, 0x94, 0x29, 0x39,
  };
  static const uint8_t kDModQMinusOne[] = {
      0x64, 0x65, 0xbd, 0x7d, 0x1a, 0x96, 0x26, 0xa1, 0xfe, 0xf3, 0x94, 0x0d,
      0x5d, 0xec, 0x85, 0xe2, 0xf8, 0xb3, 0x4c, 0xcb, 0xf9, 0x85, 0x8b, 0x12,
      0x9c, 0xa0, 0x32, 0x32, 0x35, 0x92, 0x5a, 0x94, 0x47, 0x1b, 0x70, 0xd2,
      0x90, 0x04, 0x49, 0x01, 0xd8, 0xc5, 0xe4, 0xc4, 0x43, 0xb7, 0xe9, 0x36,
      0xba, 0xbc, 0x73, 0xa8, 0xfb, 0xaf, 0x86, 0xc1, 0xd8, 0x3d, 0xcb, 0xac,
      0xf1, 0xcb, 0x60, 0x7d, 0x27, 0x21, 0xde, 0x64, 0x7f, 0xe8, 0xa8, 0x65,
      0xcc, 0x40, 0x60, 0xff, 0xa0, 0x2b, 0xfc, 0x0f, 0x80, 0x1d, 0x79, 0xca,
      0x58, 0x8a, 0xd6, 0x0f, 0xed, 0x78, 0x9a, 0x02, 0x00, 0x04, 0xc2, 0x53,
      0x41, 0xe8, 0x1a, 0xd0, 0xfd, 0x71, 0x5b, 0x43, 0xac, 0x19, 0x4a, 0xb6,
      0x12, 0xa3, 0xcb, 0xe1, 0xc7, 0x7d, 0x5c, 0x98, 0x74, 0x4e, 0x63, 0x74,
      0x6b, 0x91, 0x7a, 0x29, 0x3b, 0x92, 0xb2, 0x85,
  };
  static const uint8_t kQInverseModP[] = {
      0xd0, 0xde, 0x19, 0xda, 0x1e, 0xa2, 0xd8, 0x8f, 0x1c, 0x92, 0x73, 0xb0,
      0xc9, 0x90, 0xc7, 0xf5, 0xec, 0xc5, 0x89, 0x01, 0x05, 0x78, 0x11, 0x2d,
      0x74, 0x34, 0x44, 0xad, 0xd5, 0xf7, 0xa4, 0xfe, 0x9f, 0x25, 0x4d, 0x0b,
      0x92, 0xe3, 0xb8, 0x7d, 0xd3, 0xfd, 0xa5, 0xca, 0x95, 0x60, 0xa3, 0xf9,
      0x55, 0x42, 0x14, 0xb2, 0x45, 0x51, 0x9f, 0x73, 0x88, 0x43, 0x8a, 0xd1,
      0x65, 0x9e, 0xd1, 0xf7, 0x82, 0x2a, 0x2a, 0x8d, 0x70, 0x56, 0xe3, 0xef,
      0xc9, 0x0e, 0x2a, 0x2c, 0x15, 0xaf, 0x7f, 0x97, 0x81, 0x66, 0xf3, 0xb5,
      0x00, 0xa9, 0x26, 0xcc, 0x1e, 0xc2, 0x98, 0xdd, 0xd3, 0x37, 0x06, 0x79,
      0xb3, 0x60, 0x58, 0x79, 0x99, 0x3f, 0xa3, 0x15, 0x1f, 0x31, 0xe3, 0x11,
      0x88, 0x4c, 0x35, 0x57, 0xfa, 0x79, 0xd7, 0xd8, 0x72, 0xee, 0x73, 0x95,
      0x89, 0x29, 0xc7, 0x05, 0x27, 0x68, 0x90, 0x15,
  };

  RSA *rsa = RSA_new();
  if (rsa == NULL ||
      !set_bignum(&rsa->n, kN, sizeof(kN)) ||
      !set_bignum(&rsa->e, kE, sizeof(kE)) ||
      !set_bignum(&rsa->d, kD, sizeof(kD)) ||
      !set_bignum(&rsa->p, kP, sizeof(kP)) ||
      !set_bignum(&rsa->q, kQ, sizeof(kQ)) ||
      !set_bignum(&rsa->dmp1, kDModPMinusOne, sizeof(kDModPMinusOne)) ||
      !set_bignum(&rsa->dmq1, kDModQMinusOne, sizeof(kDModQMinusOne)) ||
      !set_bignum(&rsa->iqmp, kQInverseModP, sizeof(kQInverseModP))) {
    RSA_free(rsa);
    return NULL;
  }

  return rsa;
}

static EC_KEY *self_test_ecdsa_key(void) {
  static const uint8_t kQx[] = {
      0xc8, 0x15, 0x61, 0xec, 0xf2, 0xe5, 0x4e, 0xde, 0xfe, 0x66, 0x17,
      0xdb, 0x1c, 0x7a, 0x34, 0xa7, 0x07, 0x44, 0xdd, 0xb2, 0x61, 0xf2,
      0x69, 0xb8, 0x3d, 0xac, 0xfc, 0xd2, 0xad, 0xe5, 0xa6, 0x81,
  };
  static const uint8_t kQy[] = {
      0xe0, 0xe2, 0xaf, 0xa3, 0xf9, 0xb6, 0xab, 0xe4, 0xc6, 0x98, 0xef,
      0x64, 0x95, 0xf1, 0xbe, 0x49, 0xa3, 0x19, 0x6c, 0x50, 0x56, 0xac,
      0xb3, 0x76, 0x3f, 0xe4, 0x50, 0x7e, 0xec, 0x59, 0x6e, 0x88,
  };
  static const uint8_t kD[] = {
      0xc6, 0xc1, 0xaa, 0xda, 0x15, 0xb0, 0x76, 0x61, 0xf8, 0x14, 0x2c,
      0x6c, 0xaf, 0x0f, 0xdb, 0x24, 0x1a, 0xff, 0x2e, 0xfe, 0x46, 0xc0,
      0x93, 0x8b, 0x74, 0xf2, 0xbc, 0xc5, 0x30, 0x52, 0xb0, 0x77,
  };

  EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  BIGNUM *qx = BN_bin2bn(kQx, sizeof(kQx), NULL);
  BIGNUM *qy = BN_bin2bn(kQy, sizeof(kQy), NULL);
  BIGNUM *d = BN_bin2bn(kD, sizeof(kD), NULL);
  if (ec_key == NULL || qx == NULL || qy == NULL || d == NULL ||
      !EC_KEY_set_public_key_affine_coordinates(ec_key, qx, qy) ||
      !EC_KEY_set_private_key(ec_key, d)) {
    EC_KEY_free(ec_key);
    ec_key = NULL;
  }

  BN_free(qx);
  BN_free(qy);
  BN_free(d);
  return ec_key;
}

int BORINGSSL_self_test(
    const uint8_t module_sha512_hash[SHA512_DIGEST_LENGTH]) {
#if defined(BORINGSSL_FIPS_SELF_TEST_FLAG_FILE)
  // Test whether the flag file exists.
  char flag_path[sizeof(kFlagPrefix) + 2*SHA512_DIGEST_LENGTH];
  memcpy(flag_path, kFlagPrefix, sizeof(kFlagPrefix) - 1);
  static const char kHexTable[17] = "0123456789abcdef";
  uint8_t module_hash_sum = 0;
  for (size_t i = 0; i < SHA512_DIGEST_LENGTH; i++) {
    module_hash_sum |= module_sha512_hash[i];
    flag_path[sizeof(kFlagPrefix) - 1 + 2 * i] =
        kHexTable[module_sha512_hash[i] >> 4];
    flag_path[sizeof(kFlagPrefix) - 1 + 2 * i + 1] =
        kHexTable[module_sha512_hash[i] & 15];
  }
  flag_path[sizeof(flag_path) - 1] = 0;

  const int flag_path_valid = (module_hash_sum != 0);
  if (flag_path_valid && access(flag_path, F_OK) == 0) {
    // Flag file found. Skip self-tests.
    return 1;
  }
#endif // BORINGSSL_FIPS_SELF_TEST_FLAG_FILE

  static const uint8_t kAESKey[16] = "BoringCrypto Key";
  static const uint8_t kAESIV[16] = {0};
  static const uint8_t kPlaintext[64] =
      "BoringCryptoModule FIPS KAT Encryption and Decryption Plaintext!";
  static const uint8_t kAESCBCCiphertext[64] = {
      0x87, 0x2d, 0x98, 0xc2, 0xcc, 0x31, 0x5b, 0x41, 0xe0, 0xfa, 0x7b,
      0x0a, 0x71, 0xc0, 0x42, 0xbf, 0x4f, 0x61, 0xd0, 0x0d, 0x58, 0x8c,
      0xf7, 0x05, 0xfb, 0x94, 0x89, 0xd3, 0xbc, 0xaa, 0x1a, 0x50, 0x45,
      0x1f, 0xc3, 0x8c, 0xb8, 0x98, 0x86, 0xa3, 0xe3, 0x6c, 0xfc, 0xad,
      0x3a, 0xb5, 0x59, 0x27, 0x7d, 0x21, 0x07, 0xca, 0x4c, 0x1d, 0x55,
      0x34, 0xdd, 0x5a, 0x2d, 0xc4, 0xb4, 0xf5, 0xa8,
#if !defined(BORINGSSL_FIPS_BREAK_AES_CBC)
      0x35
#else
      0x00
#endif
  };
  static const uint8_t kAESGCMCiphertext[80] = {
      0x4a, 0xd8, 0xe7, 0x7d, 0x78, 0xd7, 0x7d, 0x5e, 0xb2, 0x11, 0xb6, 0xc9,
      0xa4, 0xbc, 0xb2, 0xae, 0xbe, 0x93, 0xd1, 0xb7, 0xfe, 0x65, 0xc1, 0x82,
      0x2a, 0xb6, 0x71, 0x5f, 0x1a, 0x7c, 0xe0, 0x1b, 0x2b, 0xe2, 0x53, 0xfa,
      0xa0, 0x47, 0xfa, 0xd7, 0x8f, 0xb1, 0x4a, 0xc4, 0xdc, 0x89, 0xf9, 0xb4,
      0x14, 0x4d, 0xde, 0x95, 0xea, 0x29, 0x69, 0x76, 0x81, 0xa3, 0x5c, 0x33,
      0xd8, 0x37, 0xd8, 0xfa, 0x47, 0x19, 0x46, 0x2f, 0xf1, 0x90, 0xb7, 0x61,
      0x8f, 0x6f, 0xdd, 0x31, 0x3f, 0x6a, 0x64,
#if !defined(BORINGSSL_FIPS_BREAK_AES_GCM)
      0x0d
#else
      0x00
#endif
  };
  static const DES_cblock kDESKey1 = {"BCMDESK1"};
  static const DES_cblock kDESKey2 = {"BCMDESK2"};
  static const DES_cblock kDESKey3 = {"BCMDESK3"};
  static const DES_cblock kDESIV = {"BCMDESIV"};
  static const uint8_t kDESCiphertext[64] = {
      0xa4, 0x30, 0x7a, 0x4c, 0x1f, 0x60, 0x16, 0xd7, 0x4f, 0x41, 0xe1,
      0xbb, 0x27, 0xc4, 0x27, 0x37, 0xd4, 0x7f, 0xb9, 0x10, 0xf8, 0xbc,
      0xaf, 0x93, 0x91, 0xb8, 0x88, 0x24, 0xb1, 0xf6, 0xf8, 0xbd, 0x31,
      0x96, 0x06, 0x76, 0xde, 0x32, 0xcd, 0x29, 0x29, 0xba, 0x70, 0x5f,
      0xea, 0xc0, 0xcb, 0xde, 0xc7, 0x75, 0x90, 0xe0, 0x0f, 0x5e, 0x2c,
      0x0d, 0x49, 0x20, 0xd5, 0x30, 0x83, 0xf8, 0x08,
#if !defined(BORINGSSL_FIPS_BREAK_DES)
      0x5a
#else
      0x00
#endif
  };
  static const uint8_t kPlaintextSHA1[20] = {
      0xc6, 0xf8, 0xc9, 0x63, 0x1c, 0x14, 0x23, 0x62, 0x9b, 0xbd,
      0x55, 0x82, 0xf4, 0xd6, 0x1d, 0xf2, 0xab, 0x7d, 0xc8,
#if !defined(BORINGSSL_FIPS_BREAK_SHA_1)
      0x28
#else
      0x00
#endif
  };
  static const uint8_t kPlaintextSHA256[32] = {
      0x37, 0xbd, 0x70, 0x53, 0x72, 0xfc, 0xd4, 0x03, 0x79, 0x70, 0xfb,
      0x06, 0x95, 0xb1, 0x2a, 0x82, 0x48, 0xe1, 0x3e, 0xf2, 0x33, 0xfb,
      0xef, 0x29, 0x81, 0x22, 0x45, 0x40, 0x43, 0x70, 0xce,
#if !defined(BORINGSSL_FIPS_BREAK_SHA_256)
      0x0f
#else
      0x00
#endif
  };
  static const uint8_t kPlaintextSHA512[64] = {
      0x08, 0x6a, 0x1c, 0x84, 0x61, 0x9d, 0x8e, 0xb3, 0xc0, 0x97, 0x4e,
      0xa1, 0x9f, 0x9c, 0xdc, 0xaf, 0x3b, 0x5c, 0x31, 0xf0, 0xf2, 0x74,
      0xc3, 0xbd, 0x6e, 0xd6, 0x1e, 0xb2, 0xbb, 0x34, 0x74, 0x72, 0x5c,
      0x51, 0x29, 0x8b, 0x87, 0x3a, 0xa3, 0xf2, 0x25, 0x23, 0xd4, 0x1c,
      0x82, 0x1b, 0xfe, 0xd3, 0xc6, 0xee, 0xb5, 0xd6, 0xaf, 0x07, 0x7b,
      0x98, 0xca, 0xa7, 0x01, 0xf3, 0x94, 0xf3, 0x68,
#if !defined(BORINGSSL_FIPS_BREAK_SHA_512)
      0x14
#else
      0x00
#endif
  };
  static const uint8_t kRSASignature[256] = {
      0x62, 0x66, 0x4b, 0xe3, 0xb1, 0xd2, 0x83, 0xf1, 0xa8, 0x56, 0x2b, 0x33,
      0x60, 0x1e, 0xdb, 0x1e, 0x06, 0xf7, 0xa7, 0x1e, 0xa8, 0xef, 0x03, 0x4d,
      0x0c, 0xf6, 0x83, 0x75, 0x7a, 0xf0, 0x14, 0xc7, 0xe2, 0x94, 0x3a, 0xb5,
      0x67, 0x56, 0xa5, 0x48, 0x7f, 0x3a, 0xa5, 0xbf, 0xf7, 0x1d, 0x44, 0xa6,
      0x34, 0xed, 0x9b, 0xd6, 0x51, 0xaa, 0x2c, 0x4e, 0xce, 0x60, 0x5f, 0xe9,
      0x0e, 0xd5, 0xcd, 0xeb, 0x23, 0x27, 0xf8, 0xfb, 0x45, 0xe5, 0x34, 0x63,
      0x77, 0x7f, 0x2e, 0x80, 0xcf, 0x9d, 0x2e, 0xfc, 0xe2, 0x50, 0x75, 0x29,
      0x46, 0xf4, 0xaf, 0x91, 0xed, 0x36, 0xe1, 0x5e, 0xef, 0x66, 0xa1, 0xff,
      0x27, 0xfc, 0x87, 0x7e, 0x60, 0x84, 0x0f, 0x54, 0x51, 0x56, 0x0f, 0x68,
      0x99, 0xc0, 0x3f, 0xeb, 0xa5, 0xa0, 0x46, 0xb0, 0x86, 0x02, 0xb0, 0xc8,
      0xe8, 0x46, 0x13, 0x06, 0xcd, 0xb7, 0x8a, 0xd0, 0x3b, 0x46, 0xd0, 0x14,
      0x64, 0x53, 0x9b, 0x5b, 0x5e, 0x02, 0x45, 0xba, 0x6e, 0x7e, 0x0a, 0xb9,
      0x9e, 0x62, 0xb7, 0xd5, 0x7a, 0x87, 0xea, 0xd3, 0x24, 0xa5, 0xef, 0xb3,
      0xdc, 0x05, 0x9c, 0x04, 0x60, 0x4b, 0xde, 0xa8, 0x90, 0x08, 0x7b, 0x6a,
      0x5f, 0xb4, 0x3f, 0xda, 0xc5, 0x1f, 0x6e, 0xd6, 0x15, 0xde, 0x65, 0xa4,
      0x6e, 0x62, 0x9d, 0x8f, 0xa8, 0xbe, 0x86, 0xf6, 0x09, 0x90, 0x40, 0xa5,
      0xf4, 0x23, 0xc5, 0xf6, 0x38, 0x86, 0x0d, 0x1c, 0xed, 0x4a, 0x0a, 0xae,
      0xa4, 0x26, 0xc2, 0x2e, 0xd3, 0x13, 0x66, 0x61, 0xea, 0x35, 0x01, 0x0e,
      0x13, 0xda, 0x78, 0x20, 0xae, 0x59, 0x5f, 0x9b, 0xa9, 0x6c, 0xf9, 0x1b,
      0xdf, 0x76, 0x53, 0xc8, 0xa7, 0xf5, 0x63, 0x6d, 0xf3, 0xff, 0xfd, 0xaf,
      0x75, 0x4b, 0xac, 0x67, 0xb1, 0x3c, 0xbf, 0x5e, 0xde, 0x73, 0x02, 0x6d,
      0xd2, 0x0c, 0xb1,
#if !defined(BORINGSSL_FIPS_BREAK_RSA_SIG)
      0x64
#else
      0x00
#endif
  };
  const uint8_t kDRBGEntropy[48] =
      "BCM Known Answer Test DBRG Initial Entropy      ";
  const uint8_t kDRBGPersonalization[18] = "BCMPersonalization";
  const uint8_t kDRBGAD[16] = "BCM DRBG KAT AD ";
  const uint8_t kDRBGOutput[64] = {
      0x1d, 0x63, 0xdf, 0x05, 0x51, 0x49, 0x22, 0x46, 0xcd, 0x9b, 0xc5,
      0xbb, 0xf1, 0x5d, 0x44, 0xae, 0x13, 0x78, 0xb1, 0xe4, 0x7c, 0xf1,
      0x96, 0x33, 0x3d, 0x60, 0xb6, 0x29, 0xd4, 0xbb, 0x6b, 0x44, 0xf9,
      0xef, 0xd9, 0xf4, 0xa2, 0xba, 0x48, 0xea, 0x39, 0x75, 0x59, 0x32,
      0xf7, 0x31, 0x2c, 0x98, 0x14, 0x2b, 0x49, 0xdf, 0x02, 0xb6, 0x5d,
      0x71, 0x09, 0x50, 0xdb, 0x23, 0xdb, 0xe5, 0x22,
#if !defined(BORINGSSL_FIPS_BREAK_DRBG)
      0x95
#else
      0x00
#endif
  };
  const uint8_t kDRBGEntropy2[48] =
      "BCM Known Answer Test DBRG Reseed Entropy       ";
  const uint8_t kDRBGReseedOutput[64] = {
      0xa4, 0x77, 0x05, 0xdb, 0x14, 0x11, 0x76, 0x71, 0x42, 0x5b, 0xd8,
      0xd7, 0xa5, 0x4f, 0x8b, 0x39, 0xf2, 0x10, 0x4a, 0x50, 0x5b, 0xa2,
      0xc8, 0xf0, 0xbb, 0x3e, 0xa1, 0xa5, 0x90, 0x7d, 0x54, 0xd9, 0xc6,
      0xb0, 0x96, 0xc0, 0x2b, 0x7e, 0x9b, 0xc9, 0xa1, 0xdd, 0x78, 0x2e,
      0xd5, 0xa8, 0x66, 0x16, 0xbd, 0x18, 0x3c, 0xf2, 0xaa, 0x7a, 0x2b,
      0x37, 0xf9, 0xab, 0x35, 0x64, 0x15, 0x01, 0x3f, 0xc4,
  };
  const uint8_t kECDSASigR[32] = {
      0x67, 0x80, 0xc5, 0xfc, 0x70, 0x27, 0x5e, 0x2c, 0x70, 0x61, 0xa0,
      0xe7, 0x87, 0x7b, 0xb1, 0x74, 0xde, 0xad, 0xeb, 0x98, 0x87, 0x02,
      0x7f, 0x3f, 0xa8, 0x36, 0x54, 0x15, 0x8b, 0xa7, 0xf5,
#if !defined(BORINGSSL_FIPS_BREAK_ECDSA_SIG)
      0x0c,
#else
      0x00,
#endif
  };
  const uint8_t kECDSASigS[32] = {
      0xa5, 0x93, 0xe0, 0x23, 0x91, 0xe7, 0x4b, 0x8d, 0x77, 0x25, 0xa6,
      0xba, 0x4d, 0xd9, 0x86, 0x77, 0xda, 0x7d, 0x8f, 0xef, 0xc4, 0x1a,
      0xf0, 0xcc, 0x81, 0xe5, 0xea, 0x3f, 0xc2, 0x41, 0x7f, 0xd8,
  };

  EVP_AEAD_CTX aead_ctx;
  EVP_AEAD_CTX_zero(&aead_ctx);
  RSA *rsa_key = NULL;
  EC_KEY *ec_key = NULL;
  ECDSA_SIG *sig = NULL;
  int ret = 0;

  AES_KEY aes_key;
  uint8_t aes_iv[16];
  uint8_t output[256];

  // AES-CBC Encryption KAT
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  if (AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) != 0) {
    fprintf(stderr, "AES_set_encrypt_key failed.\n");
    goto err;
  }
  AES_cbc_encrypt(kPlaintext, output, sizeof(kPlaintext), &aes_key, aes_iv,
                  AES_ENCRYPT);
  if (!check_test(kAESCBCCiphertext, output, sizeof(kAESCBCCiphertext),
                  "AES-CBC Encryption KAT")) {
    goto err;
  }

  // AES-CBC Decryption KAT
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  if (AES_set_decrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) != 0) {
    fprintf(stderr, "AES_set_decrypt_key failed.\n");
    goto err;
  }
  AES_cbc_encrypt(kAESCBCCiphertext, output, sizeof(kAESCBCCiphertext),
                  &aes_key, aes_iv, AES_DECRYPT);
  if (!check_test(kPlaintext, output, sizeof(kPlaintext),
                  "AES-CBC Decryption KAT")) {
    goto err;
  }

  size_t out_len;
  uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH];
  OPENSSL_memset(nonce, 0, sizeof(nonce));
  if (!EVP_AEAD_CTX_init(&aead_ctx, EVP_aead_aes_128_gcm(), kAESKey,
                         sizeof(kAESKey), 0, NULL)) {
    fprintf(stderr, "EVP_AEAD_CTX_init for AES-128-GCM failed.\n");
    goto err;
  }

  // AES-GCM Encryption KAT
  if (!EVP_AEAD_CTX_seal(&aead_ctx, output, &out_len, sizeof(output), nonce,
                         EVP_AEAD_nonce_length(EVP_aead_aes_128_gcm()),
                         kPlaintext, sizeof(kPlaintext), NULL, 0) ||
      !check_test(kAESGCMCiphertext, output, sizeof(kAESGCMCiphertext),
                  "AES-GCM Encryption KAT")) {
    fprintf(stderr, "EVP_AEAD_CTX_seal for AES-128-GCM failed.\n");
    goto err;
  }

  // AES-GCM Decryption KAT
  if (!EVP_AEAD_CTX_open(&aead_ctx, output, &out_len, sizeof(output), nonce,
                         EVP_AEAD_nonce_length(EVP_aead_aes_128_gcm()),
                         kAESGCMCiphertext, sizeof(kAESGCMCiphertext), NULL,
                         0) ||
      !check_test(kPlaintext, output, sizeof(kPlaintext),
                  "AES-GCM Decryption KAT")) {
    fprintf(stderr, "EVP_AEAD_CTX_open for AES-128-GCM failed.\n");
    goto err;
  }

  DES_key_schedule des1, des2, des3;
  DES_cblock des_iv;
  DES_set_key(&kDESKey1, &des1);
  DES_set_key(&kDESKey2, &des2);
  DES_set_key(&kDESKey3, &des3);

  // 3DES Encryption KAT
  memcpy(&des_iv, &kDESIV, sizeof(des_iv));
  DES_ede3_cbc_encrypt(kPlaintext, output, sizeof(kPlaintext), &des1, &des2,
                       &des3, &des_iv, DES_ENCRYPT);
  if (!check_test(kDESCiphertext, output, sizeof(kDESCiphertext),
                  "3DES Encryption KAT")) {
    goto err;
  }

  // 3DES Decryption KAT
  memcpy(&des_iv, &kDESIV, sizeof(des_iv));
  DES_ede3_cbc_encrypt(kDESCiphertext, output, sizeof(kDESCiphertext), &des1,
                       &des2, &des3, &des_iv, DES_DECRYPT);
  if (!check_test(kPlaintext, output, sizeof(kPlaintext),
                  "3DES Decryption KAT")) {
    goto err;
  }

  // SHA-1 KAT
  SHA1(kPlaintext, sizeof(kPlaintext), output);
  if (!check_test(kPlaintextSHA1, output, sizeof(kPlaintextSHA1),
                  "SHA-1 KAT")) {
    goto err;
  }

  // SHA-256 KAT
  SHA256(kPlaintext, sizeof(kPlaintext), output);
  if (!check_test(kPlaintextSHA256, output, sizeof(kPlaintextSHA256),
                  "SHA-256 KAT")) {
    goto err;
  }

  // SHA-512 KAT
  SHA512(kPlaintext, sizeof(kPlaintext), output);
  if (!check_test(kPlaintextSHA512, output, sizeof(kPlaintextSHA512),
                  "SHA-512 KAT")) {
    goto err;
  }

  rsa_key = self_test_rsa_key();
  if (rsa_key == NULL) {
    fprintf(stderr, "RSA KeyGen failed\n");
    goto err;
  }

  // RSA Sign KAT
  unsigned sig_len;

  // Disable blinding for the power-on tests because it's not needed and
  // triggers an entropy draw.
  rsa_key->flags |= RSA_FLAG_NO_BLINDING;

  if (!RSA_sign(NID_sha256, kPlaintextSHA256, sizeof(kPlaintextSHA256), output,
                &sig_len, rsa_key) ||
      !check_test(kRSASignature, output, sizeof(kRSASignature),
                  "RSA Sign KAT")) {
    fprintf(stderr, "RSA signing test failed.\n");
    goto err;
  }

  // RSA Verify KAT
  if (!RSA_verify(NID_sha256, kPlaintextSHA256, sizeof(kPlaintextSHA256),
                  kRSASignature, sizeof(kRSASignature), rsa_key)) {
    fprintf(stderr, "RSA Verify KAT failed.\n");
    goto err;
  }

  ec_key = self_test_ecdsa_key();
  if (ec_key == NULL) {
    fprintf(stderr, "ECDSA KeyGen failed\n");
    goto err;
  }

  // ECDSA Sign/Verify PWCT

  // The 'k' value for ECDSA is fixed to avoid an entropy draw.
  ec_key->fixed_k = BN_new();
  if (ec_key->fixed_k == NULL ||
      !BN_set_word(ec_key->fixed_k, 42)) {
    fprintf(stderr, "Out of memory\n");
    goto err;
  }

  sig = ECDSA_do_sign(kPlaintextSHA256, sizeof(kPlaintextSHA256), ec_key);

  uint8_t ecdsa_r_bytes[sizeof(kECDSASigR)];
  uint8_t ecdsa_s_bytes[sizeof(kECDSASigS)];
  if (sig == NULL ||
      BN_num_bytes(sig->r) != sizeof(ecdsa_r_bytes) ||
      !BN_bn2bin(sig->r, ecdsa_r_bytes) ||
      BN_num_bytes(sig->s) != sizeof(ecdsa_s_bytes) ||
      !BN_bn2bin(sig->s, ecdsa_s_bytes) ||
      !check_test(kECDSASigR, ecdsa_r_bytes, sizeof(kECDSASigR), "ECDSA R") ||
      !check_test(kECDSASigS, ecdsa_s_bytes, sizeof(kECDSASigS), "ECDSA S")) {
    fprintf(stderr, "ECDSA KAT failed.\n");
    goto err;
  }

  // DBRG KAT
  CTR_DRBG_STATE drbg;
  if (!CTR_DRBG_init(&drbg, kDRBGEntropy, kDRBGPersonalization,
                     sizeof(kDRBGPersonalization)) ||
      !CTR_DRBG_generate(&drbg, output, sizeof(kDRBGOutput), kDRBGAD,
                         sizeof(kDRBGAD)) ||
      !check_test(kDRBGOutput, output, sizeof(kDRBGOutput),
                  "DBRG Generate KAT") ||
      !CTR_DRBG_reseed(&drbg, kDRBGEntropy2, kDRBGAD, sizeof(kDRBGAD)) ||
      !CTR_DRBG_generate(&drbg, output, sizeof(kDRBGReseedOutput), kDRBGAD,
                         sizeof(kDRBGAD)) ||
      !check_test(kDRBGReseedOutput, output, sizeof(kDRBGReseedOutput),
                  "DRBG Reseed KAT")) {
    fprintf(stderr, "CTR-DRBG failed.\n");
    goto err;
  }
  CTR_DRBG_clear(&drbg);

  CTR_DRBG_STATE kZeroDRBG;
  memset(&kZeroDRBG, 0, sizeof(kZeroDRBG));
  if (!check_test(&kZeroDRBG, &drbg, sizeof(drbg), "DRBG Clear KAT")) {
    goto err;
  }

  ret = 1;

#if defined(BORINGSSL_FIPS_SELF_TEST_FLAG_FILE)
  // Tests were successful. Write flag file if requested.
  if (flag_path_valid && (getenv(kFlagVariable) != NULL)) {
    const int fd = open(flag_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
      close(fd);
    }
  }
#endif  // BORINGSSL_FIPS_SELF_TEST_FLAG_FILE

err:
  EVP_AEAD_CTX_cleanup(&aead_ctx);
  RSA_free(rsa_key);
  EC_KEY_free(ec_key);
  ECDSA_SIG_free(sig);

  return ret;
}

#endif  // !_MSC_VER
