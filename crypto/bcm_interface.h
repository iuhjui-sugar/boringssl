/* Copyright (c) 2024, Google Inc.
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

#ifndef OPENSSL_HEADER_CRYPTO_BCM_TNTERFACE_H
#define OPENSSL_HEADER_CRYPTO_BCM_TNTERFACE_H

#include "rand_extra/sysrand.h"

/* Interface between bcm and the rest of libcrypto */

#if defined(__cplusplus)
extern "C" {
#endif

/* Provided by libcrypto, called from BCM */

#if defined(OPENSSL_RAND_URANDOM)
// CRYPTO_sysrand_if_available fills |len| bytes at |buf| with entropy from the
// operating system, or early /dev/urandom data, and returns 1, _if_ the entropy
// pool is initialized or if getrandom() is not available and not in FIPS mode.
// Otherwise it will not block and will instead fill |buf| with all zeros and
// return 0.
int CRYPTO_sysrand_if_available(uint8_t *buf, size_t len);
#else
// XXX XXX internalize this rather than have it here.
OPENSSL_INLINE int CRYPTO_sysrand_if_available(uint8_t *buf, size_t len) {
  CRYPTO_sysrand(buf, len);
  return 1;
}
#endif  // defined(OPENSSL_RAND_URANDOM)

// CRYPTO_sysrand_for_seed fills |len| bytes at |buf| with entropy from the
// operating system. It may draw from the |GRND_RANDOM| pool on Android,
// depending on the vendor's configuration.
void CRYPTO_sysrand_for_seed(uint8_t *buf, size_t len);

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CRYPTO_BCM_TNTERFACE_H
