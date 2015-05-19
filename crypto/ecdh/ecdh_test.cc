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

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/obj.h>

#include "../test/scoped_types.h"


static bool TestCompute() {
  ScopedEC_GROUP p256(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  ScopedEC_GROUP p384(EC_GROUP_new_by_curve_name(NID_secp384r1));

  ScopedEC_KEY key256(EC_KEY_new());
  ScopedEC_KEY key384(EC_KEY_new());
  if (!EC_KEY_set_group(key256.get(), p256.get()) ||
      !EC_KEY_set_group(key384.get(), p384.get()) ||
      !EC_KEY_generate_key(key256.get()) ||
      !EC_KEY_generate_key(key384.get())) {
    return false;
  }

  uint8_t out[32];
  if (ECDH_compute_key(out, sizeof(out), EC_KEY_get0_public_key(key256.get()),
                       key384.get(), NULL) != -1) {
    fprintf(stderr,
            "ECDH_compute_key completed successfully with distinct groups.\n");
    return false;
  }

  return true;
}

int main(int argc, char *argv[]) {
  if (!TestCompute()) {
    ERR_print_errors_fp(stderr);
    return 1;
  }

  printf("PASS\n");
  return 0;
}
