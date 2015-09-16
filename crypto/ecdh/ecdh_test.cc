/* Copyright (c) 2015, Google Inc.
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

#include <stdio.h>

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>

#include "../test/scoped_types.h"


static bool TestECDH(int nid) {
  ScopedEC_KEY key1(EC_KEY_new_by_curve_name(nid));
  ScopedEC_KEY key2(EC_KEY_new_by_curve_name(nid));
  if (!key1 || !key2) {
    return false;
  }

  const EC_GROUP *group = EC_KEY_get0_group(key1.get());

  if (!EC_KEY_generate_key(key1.get()) ||
      !EC_KEY_generate_key(key2.get())) {
    fprintf(stderr, "EC_KEY_generate_key failed with nid %d\n", nid);
    ERR_print_errors_fp(stderr);
    return false;
  }

  uint8_t buf[1];
  if (ECDH_compute_key(buf, sizeof(buf), EC_KEY_get0_public_key(key2.get()),
                       key1.get(), nullptr) == -1) {
    fprintf(stderr, "ECDH_compute_key failed with a valid point with nid %d.\n",
            nid);
    ERR_print_errors_fp(stderr);
    return false;
  }

  ScopedBIGNUM x(BN_new());
  ScopedBIGNUM y(BN_new());
  if (!EC_POINT_get_affine_coordinates_GFp(group,
                                           EC_KEY_get0_public_key(key2.get()),
                                           x.get(), y.get(), nullptr)) {
    fprintf(stderr, "EC_POINT_get_affine_coordinates_GFp failed with nid %d\n",
            nid);
    ERR_print_errors_fp(stderr);
    return false;
  }

  // Subtract one from |y| to make the point no longer on the curve.
  if (!BN_sub(y.get(), y.get(), BN_value_one())) {
    return false;
  }

  ScopedEC_POINT invalid_point(EC_POINT_new(group));
  if (!invalid_point) {
    return false;
  }

  if (!EC_POINT_set_affine_coordinates_GFp(group, invalid_point.get(), x.get(),
                                           y.get(), nullptr)) {
    fprintf(stderr, "EC_POINT_set_affine_coordinates_GFp failed with nid %d\n",
            nid);
    ERR_print_errors_fp(stderr);
    return false;
  }

  if (ECDH_compute_key(buf, sizeof(buf), invalid_point.get(), key1.get(),
                       nullptr) != -1) {
    fprintf(stderr,
            "ECDH_compute_key succeeded with an invalid point with nid %d.\n",
            nid);
    return false;
  }
  ERR_clear_error();

  return true;
}

int main(void) {
  if (!TestECDH(NID_X9_62_prime256v1) ||
      !TestECDH(NID_secp224r1) ||
      !TestECDH(NID_secp384r1) ||
      !TestECDH(NID_secp521r1)) {
    fprintf(stderr, "failed\n");
    return 1;
  }

  printf("PASS\n");
  return 0;
}
