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

#ifndef OPENSSL_HEADER_CRYPTO_BCM_INTERFACE_H
#define OPENSSL_HEADER_CRYPTO_BCM_INTERFACE_H

/* Interface between bcm and the rest of libcrypto */

#if defined(__cplusplus)
extern "C" {
#endif

enum bcm_status_t
{
  // Success codes - corresponding to FIPS
  BCM_STATUS_APPROVED,
  BCM_STATUS_NOT_APPROVED,

  // Failure codes
  BCM_STATUS_FAILURE,
};
typedef enum bcm_status_t bcm_status;

OPENSSL_INLINE int BCM_SUCCESS(bcm_status status) {
  return status == BCM_STATUS_APPROVED || status == BCM_STATUS_NOT_APPROVED;
}

#if defined(BORINGSSL_FIPS)

// We overread from /dev/urandom or RDRAND by a factor of 10 and XOR to whiten.
#define BORINGSSL_FIPS_OVERREAD 10

#endif  // BORINGSSL_FIPS

// Provided by BCM

// BCM_RAND_bytes is the same as the public |RAND_bytes| function, but
// returns BCM_STATUS_APPROVED for success, and BCM_FAILURE for failure.
OPENSSL_EXPORT bcm_status BCM_RAND_bytes(uint8_t *out, size_t out_len);

// BCM_RAND_bytes_hwrng attempts to fill |out| with |len| bytes of entropy from
// the CPU hardware random number generator if one is present. If |fast| is
// non-zero this will only succeed if the CPU hwrng is thought to be "fast". On
// success BCM_STATUS_NOT_APPROVED is returned, BCM_STATUS_FAILURE is returned
// otherwise.
bcm_status BCM_RAND_bytes_hwrng(uint8_t *out, const size_t len, int fast);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CRYPTO_BCM_INTERFACE_H
