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

#include <assert.h>

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/span.h>

// Basic implementation of mod_exp using square and multiple method.
int mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
            BN_CTX *ctx) {
  if (BN_is_one(m)) {
    BN_zero(r);
    return 1;
  }

  bssl::UniquePtr<BIGNUM> exp(BN_dup(p));
  bssl::UniquePtr<BIGNUM> base(BN_new());
  if (!exp || !base) {
    return 0;
  }
  if (!BN_one(r) || !BN_nnmod(base.get(), a, m, ctx)) {
    return 0;
  }

  while (!BN_is_zero(exp.get())) {
    if (BN_is_odd(exp.get())) {
      if (!BN_mul(r, r, base.get(), ctx) || !BN_nnmod(r, r, m, ctx)) {
        return 0;
      }
    }
    if (!BN_rshift1(exp.get(), exp.get()) ||
        !BN_mul(base.get(), base.get(), base.get(), ctx) ||
        !BN_nnmod(base.get(), base.get(), m, ctx)) {
      return 0;
    }
  }

  return 1;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  CBS cbs, vcbs0, vcbs1, vcbs2;
  uint8_t sign0, sign1, sign2;
  CBS_init(&cbs, buf, len);
  if (!CBS_get_u8_length_prefixed(&cbs, &vcbs0) ||
      !CBS_get_u8(&vcbs0, &sign0) ||
      CBS_len(&vcbs0) == 0 ||
      !CBS_get_u8_length_prefixed(&cbs, &vcbs1) ||
      !CBS_get_u8(&vcbs1, &sign1) ||
      CBS_len(&vcbs1) == 0 ||
      !CBS_get_u8_length_prefixed(&cbs, &vcbs2) ||
      !CBS_get_u8(&vcbs2, &sign2) ||
      CBS_len(&vcbs2) == 0) {
    return 0;
  }

  bssl::Span<const uint8_t> s0(vcbs0);
  bssl::UniquePtr<BIGNUM> bn0(BN_bin2bn(s0.data(), s0.size(), nullptr));
  BN_set_negative(bn0.get(), sign0 % 2);

  bssl::Span<const uint8_t> s1(vcbs1);
  bssl::UniquePtr<BIGNUM> bn1(BN_bin2bn(s1.data(), s1.size(), nullptr));
  BN_set_negative(bn1.get(), sign1 % 2);

  bssl::Span<const uint8_t> s2(vcbs2);
  bssl::UniquePtr<BIGNUM> bn2(BN_bin2bn(s2.data(), s2.size(), nullptr));
  BN_set_negative(bn2.get(), sign2 % 2);

  bssl::UniquePtr<BN_CTX> ctx(BN_CTX_new());
  bssl::UniquePtr<BIGNUM> bnr(BN_new());
  bssl::UniquePtr<BIGNUM> bnq(BN_new());
  if (!ctx || !bnr || !bnq) {
    return 0;
  }
  assert(BN_add(bnr.get(), bn0.get(), bn1.get()));
  assert(BN_sub(bnr.get(), bn0.get(), bn1.get()));
  assert(BN_mul(bnr.get(), bn0.get(), bn1.get(), ctx.get()));

  if (!BN_is_zero(bn1.get())) {
    assert(BN_div(bnr.get(), bnq.get(), bn0.get(), bn1.get(), ctx.get()));
  }

  if (!BN_is_zero(bn2.get()) &&
      !BN_is_negative(bn1.get()) &&
      !BN_is_negative(bn2.get())) {
    assert(BN_mod_exp(bnr.get(), bn0.get(), bn1.get(), bn2.get(), ctx.get()));
    assert(mod_exp(bnq.get(), bn0.get(), bn1.get(), bn2.get(), ctx.get()));
    assert(BN_cmp(bnr.get(), bnq.get()) == 0);
  }

  uint8_t *data = (uint8_t *)OPENSSL_malloc(BN_num_bytes(bnr.get()));
  BN_bn2bin(bnr.get(), data);
  OPENSSL_free(data);

  return 0;
}
