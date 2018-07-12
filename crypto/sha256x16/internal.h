/* Copyright (c) 2018, Google Inc.
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

#ifndef OPENSSL_HEADER_SHA256x16_INTERNAL_H
#define OPENSSL_HEADER_SHA256x16_INTERNAL_H

#include <openssl/base.h>


// state contains the state of the 16 SHA-256 hashes. In the generic code, the
// representation is obvious: each SHA-256 was eight words of state and that
// structure is repeated 16 times.
//
// With a vector unit in hand, one wants to compute n lanes in an n-word vector.
// The way that the input is assigned to different lanes is designed to be
// compatible with this: just reading the input into a vector register puts
// things in the right place for this design. Thus with a 4-word vector (e.g.
// AVX), the state will contain eight vectors for each group of four lanes. The
// first vector, for example, will contain the first word of the SHA-256 state
// for lanes zero though three.
struct state {
  union {
    uint32_t generic[8*16];
#if defined(AVX)
    __m128i avx[8+8+8+8];
#endif
#if defined(AVX2)
    // With an 8-word vector, only two groups of eight lanes are needed.
    __m256i avx2[8+8];
#endif
  } u;
};

// kInitialValues is the starting state for SHA-256.
static const uint32_t kInitialValues[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                           0xa54ff53a, 0x510e527f, 0x9b05688c,
                                           0x1f83d9ab, 0x5be0cd19};


#endif  // OPENSSL_HEADER_SHA256x16_INTERNAL_H
