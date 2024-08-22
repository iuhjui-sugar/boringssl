/*
 * Copyright 2014-2016 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2014, Intel Corporation. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Shay Gueron (1, 2), and Vlad Krasnov (1)
 * (1) Intel Corporation, Israel Development Center, Haifa, Israel
 * (2) University of Haifa, Israel
 *
 * Reference:
 * S.Gueron and V.Krasnov, "Fast Prime Field Elliptic Curve Cryptography with
 *                          256 Bit Primes"
 */

#ifndef OPENSSL_HEADER_EC_P256_X86_64_H
#define OPENSSL_HEADER_EC_P256_X86_64_H

#include <openssl/base.h>

#include <openssl/bn.h>

#include "../bn/internal.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define P256_LIMBS (256 / BN_BITS2)

// P-256 scalar operations.
//
// The following functions compute modulo N, where N is the order of P-256. They
// take fully-reduced inputs and give fully-reduced outputs.

// ecp_nistz256_ord_mul_mont sets |res| to |a| * |b| where inputs and outputs
// are in Montgomery form. That is, |res| is |a| * |b| * 2^-256 mod N.
void ecp_nistz256_ord_mul_mont(BN_ULONG res[P256_LIMBS],
                               const BN_ULONG a[P256_LIMBS],
                               const BN_ULONG b[P256_LIMBS]);
void ecp_nistz256_ord_mul_montx(BN_ULONG res[P256_LIMBS],
                               const BN_ULONG a[P256_LIMBS],
                               const BN_ULONG b[P256_LIMBS]);

// ecp_nistz256_ord_sqr_mont sets |res| to |a|^(2*|rep|) where inputs and
// outputs are in Montgomery form. That is, |res| is
// (|a| * 2^-256)^(2*|rep|) * 2^256 mod N.
void ecp_nistz256_ord_sqr_mont(BN_ULONG res[P256_LIMBS],
                               const BN_ULONG a[P256_LIMBS], BN_ULONG rep);
void ecp_nistz256_ord_sqr_montx(BN_ULONG res[P256_LIMBS],
                               const BN_ULONG a[P256_LIMBS], BN_ULONG rep);

// beeu_mod_inverse_vartime sets out = a^-1 mod p using a Euclidean algorithm.
// Assumption: 0 < a < p < 2^(256) and p is odd.
int beeu_mod_inverse_vartime(BN_ULONG out[P256_LIMBS],
                             const BN_ULONG a[P256_LIMBS],
                             const BN_ULONG p[P256_LIMBS]);

#if defined(__cplusplus)
}  // extern C++
#endif

#endif  // OPENSSL_HEADER_EC_P256_X86_64_H
