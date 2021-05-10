/* Copyright (c) 2021, Google Inc.
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

#include "openssl/base.h"

#include "../../crypto/fipsmodule/ec/internal.h"

EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a,
                                 const BIGNUM *b, BN_CTX *ctx) {
  return ec_group_new_curve_GFp(p, a, b, ctx);
}

int EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator,
                           const BIGNUM *order, const BIGNUM *cofactor) {
  return ec_group_set_generator(group, generator, order, cofactor);
}
