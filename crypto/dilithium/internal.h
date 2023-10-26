/* Copyright (c) 2023, Google Inc.
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

#ifndef OPENSSL_HEADER_CRYPTO_DILITHIUM_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_DILITHIUM_INTERNAL_H

#include <openssl/base.h>
#include <openssl/dilithium.h>

#if defined(__cplusplus)
extern "C" {
#endif


// DILITHIUM_GENERATE_KEY_ENTROPY is the number of bytes of uniformly random
// entropy necessary to generate a key pair.
#define DILITHIUM_GENERATE_KEY_ENTROPY 32

void DILITHIUM_generate_key_external_entropy(
    uint8_t out_encoded_public_key[DILITHIUM_PUBLIC_KEY_BYTES],
    struct DILITHIUM_private_key *out_private_key,
    const uint8_t entropy[DILITHIUM_GENERATE_KEY_ENTROPY]);

// TODO(guillaumee): add randomized signature variant.


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CRYPTO_DILITHIUM_INTERNAL_H
