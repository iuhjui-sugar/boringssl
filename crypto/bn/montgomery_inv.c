/* Copyright 2016 Brian Smith.
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

#include <openssl/bn.h>

#include <assert.h>

#include "internal.h"
#include "../internal.h"


static uint64_t xbinGCD(uint64_t a_half, uint64_t b);

OPENSSL_COMPILE_ASSERT(BN_MONT_CTX_N0_LIMBS == 1 || BN_MONT_CTX_N0_LIMBS == 2,
                       BN_MONT_CTX_N0_LIMBS_VALUE_INVALID);
OPENSSL_COMPILE_ASSERT(sizeof(uint64_t) ==
                       BN_MONT_CTX_N0_LIMBS * sizeof(BN_ULONG),
                       BN_MONT_CTX_N0_LIMBS_DOES_NOT_MATCH_UINT64_T);

uint64_t bn_mont_n0(const BIGNUM *n) {
  /* r = 2**(BN_MONT_CTX_N0_LIMBS * BN_BITS2). kLgR == lg(r). |r| being a power
   * of |BN_BITS2| ensures that we can do integer division by |r| by simply
   * ignoring |BN_MONT_CTX_N0_LIMBS| limbs. Similarly, we can calculate values
   * modulo |r| by just looking at the lowest |BN_MONT_CTX_N0_LIMBS| limbs.
   * This is what makes Montgomery multiplication efficient.
   *
   * As shown in Algorithm 1 of "Fast Prime Field Elliptic Curve Cryptography
   * with 256 Bit Primes" by Shay Gueron and Vlad Krasnov, in the inner loop of
   * a multi-limb Montgomery multiplication of |a * b (mod N)| we repeatedly
   * calculate, given the unreduced product |t = a * b|:
   *
   *    t1 := t % r         |t1| is |t|'s lowest limb (see previous paragraph).
   *    t2 := t1 * n0 * N
   *    t3 := t + t2
   *    t := t3 / r         copy all limbs of |t3| except the lowest to |t|.
   *
   * In the last step, it would only make sense to ignore the lowest limb of
   * |t3| if it were zero. The middle steps ensure that this is the case:
   *
   *                            t3 ==  0 (mod r)
   *                        t + t2 ==  0 (mod r)
   *                   t + t1*n0*N ==  0 (mod r)
   *                       t1*n0*N == -t (mod r)
   *                        t*n0*N == -t (mod r)
   *                          n0*N == -1 (mod r)
   *                            n0 == -1/n (mod r)
   *
   * Thus, in each iteration of the loop, we multiply by constant factor |n0|,
   * which is the negative inverse of |N| (mod r). */
  static const unsigned kLgLittleR = BN_MONT_CTX_N0_LIMBS * BN_BITS2;

  /* n_mod_r = n % r. As explained above, this is equivalent to taking the
   * lowest |BN_MONT_CTX_N0_LIMBS| limbs of |n|. */
  uint64_t n_mod_r = n->d[0];
#if BN_MONT_CTX_N0_LIMBS == 2
  if (n->top > 1) {
    n_mod_r |= (uint64_t)n->d[1] << BN_BITS2;
  }
#endif

  uint64_t r_half = (uint64_t)1 << (kLgLittleR - 1); /* r_half = r / 2. */
  return xbinGCD(r_half, n_mod_r);
}

/* xbinGCD calculates |v| such that |u*a - v*b == 1| where |a_half == a / 2|.
 * |a_half| must be a power of 2 and |b| must be odd.
 *
 * |a_half| is passed instead of |a| so that the function works for a == 2**64,
 * which doesn't fit in a |uint64_t|.
 *
 * Most GCD implementations return values such that |u*a + v*b == 1|, so the
 * caller would have to negate the resultant |v| for the purpose of Montgomery
 * multiplication. This implementation does the negation implicitly by
 * doing the computations as a difference instead of a sum.
 *
 * This is derived from the "Montgomery Multiplication" chapter of
 * "Hacker's Delight" by Henry S. Warren, Jr.:
 * http://www.hackersdelight.org/MontgomeryMultiplication.pdf.
 *
 * This is inspired by Joppe W. Bos's "Constant Time Modular Inversion"
 * http://www.joppebos.com/files/CTInversion.pdf so that the inversion is
 * constant-time with respect to |b|. We assume |a| is not secret. We assume
 * uint64_t additions, subtractions, shifts, and bitwise operations are all
 * constant time, which may be a large leap of faith on 32-bit targets. We
 * avoid division and multiplication, which tend to be the most problematic in
 * terms of timing leaks. */
static uint64_t xbinGCD(uint64_t a_half, uint64_t b) {
  assert(a_half % 2 == 0);
  assert(b % 2 == 1);

  uint64_t a = a_half; /* i.e. |a >>= 1| if |a| were the parameter. */
  uint64_t alpha = a_half;
  uint64_t beta = b;
  uint64_t u = 1;
  uint64_t v = 0;

  /* The invariant maintained from here on is: a = u*2*alpha - v*beta. */
  while (a != 0) {
    a >>= 1;

    /* Either we will delete a common factor of 2 in u and v... */
    uint64_t u_div_2 = u >> 1;
    uint64_t v_div_2 = v >> 1;

    /* ...or we will set |u = (u + beta) / 2| and |v = (v / 2) + alpha|. The
     * addition for |u| can overflow, so use Dietz's method for it. */
    uint64_t u_plus_beta_div_2 = ((u ^ beta) >> 1) + (u & beta);
    uint64_t v_div_2_plus_alpha = (v >> 1) + alpha;

    uint64_t u_is_odd = UINT64_C(0) - (u & 1);
    u = constant_time_select_uint64_t(u_is_odd, u_plus_beta_div_2, u_div_2);
    assert(u_is_odd ? (u == u_plus_beta_div_2) : (u == u_div_2));
    v = constant_time_select_uint64_t(u_is_odd, v_div_2_plus_alpha, v_div_2);
    assert(u_is_odd ? (v == v_div_2_plus_alpha) : (v == v_div_2));
  }

  return v;
}
