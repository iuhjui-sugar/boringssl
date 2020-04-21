// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENSSL_HEADER_EC_P384_X86_64_H
#define OPENSSL_HEADER_EC_P384_X86_64_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


#if !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86_64) && \
    !defined(OPENSSL_SMALL)

// P-384 field operations.
//
// An element mod P in P-384 is represented as a little-endian array of
// |P384_LIMBS| |BN_ULONG|s, spanning the full range of values.
//
// The following functions take fully-reduced inputs mod P and give
// fully-reduced outputs. They may be used in-place.
#define P384_LIMBS (384 / BN_BITS2)

// A P384_POINT_AFFINE represents a P-384 point in affine coordinates. Infinity
// is encoded as (0, 0).
typedef struct {
  BN_ULONG X[P384_LIMBS];
  BN_ULONG Y[P384_LIMBS];
} P384_POINT_AFFINE;

// ecp_nistp384_select_w7 sets |*val| to |in_t[index-1]| if 1 <= |index| <= 64
// and all zeros (the point at infinity) if |index| is 0. This is done in
// constant time.
void ecp_nistp384_select_w7(P384_POINT_AFFINE *val,
                            const P384_POINT_AFFINE in_t[64], int index);

#endif /* !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86_64) && \
           !defined(OPENSSL_SMALL) */


#if defined(__cplusplus)
}  // extern C++
#endif

#endif  // OPENSSL_HEADER_EC_P384_X86_64_H
