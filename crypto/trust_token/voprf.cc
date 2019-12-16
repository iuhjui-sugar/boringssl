/* Copyright (c) 2019, Google Inc.
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

#include <openssl/trust_token.h>

#include "internal.h"

EC_KEY *VOPRF_Setup(uint16_t ciphersuite) {
  // TODO: Support other ciphersuites.
  if (ciphersuite != 0x4242) {
    return nullptr;
  }

  EC_KEY *key(EC_KEY_new_by_curve_name(NID_secp521r1));
  if (!EC_KEY_generate_key(key)) {
    return nullptr;
  }

  return key;
}

// bool VOPRF_Blind(GF(p), X, r, M) {
//   // p = ciphersuite->prime_order
//   // k <-$ GF(p)



//   aInput:

//  l: Some suitable choice of prime length for instantiating a group structure
//     (e.g. as described in [NIST]).

// Output:

//  k: A key chosen from {0,1}^l and interpreted as an integer value.

// Steps:

//  1. Let GG = GG(l) be a group with prime-order p of length l bits
//  2. Sample a uniform scalar k <-$ GF(p)
//  3. Output (k,p)

//      k =
//      k,p =
//   (r, M)


// }

// Key, curve/G, Y (public key), M
// void VOPRF_Eval() {
//   // bssl::UniquePtr<BN_CTX> ctx(BN_CTX_new());
//   // ASSERT_TRUE(ctx);

//   // UniquePtr<EC_GROUP> p256(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
//   // bssl::UniquePtr<BIGNUM> n = GetBIGNUM(t, "N");
//   // ASSERT_TRUE(n);
//   // bssl::UniquePtr<BIGNUM> x = GetBIGNUM(t, "X");
//   // ASSERT_TRUE(x);
//   // bssl::UniquePtr<BIGNUM> y = GetBIGNUM(t, "Y");
//   // ASSERT_TRUE(y);
//   // bool is_infinity = BN_is_zero(x.get()) && BN_is_zero(y.get());

//   // bssl::UniquePtr<BIGNUM> px(BN_new());
//   // ASSERT_TRUE(px);
//   // bssl::UniquePtr<BIGNUM> py(BN_new());
//   // ASSERT_TRUE(py);

//   // const EC_POINT *G = EC_GROUP_get0_generator(group.get());
//   // Z = k*M
//   //     Z = hZ
//   // D = DLEQ_Generate(k, G, Y, M, Z)
//   //     Output (Z, D)
//   // bssl::UniquePtr<EC_POINT> p(EC_POINT_new(group.get()));
//   // ASSERT_TRUE(p);
//   // // Test single-point multiplication.
//   // ASSERT_TRUE(EC_POINT_mul(group.get(), p.get(), n.get(), nullptr, nullptr,
//   //                          ctx.get()));

//   // ASSERT_TRUE(
//   //     EC_POINT_mul(group.get(), p.get(), nullptr, g, n.get(), ctx.get()));
// }
