/* Copyright (c) 2024, Google LLC
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

#ifndef OPENSSL_HEADER_CRYPTO_MLDSA_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_MLDSA_INTERNAL_H

#include <openssl/base.h>
#include <openssl/mldsa.h>

#if defined(__cplusplus)
extern "C" {
#endif


// MLDSA_GENERATE_KEY_ENTROPY is the number of bytes of uniformly random
// entropy necessary to generate a key pair.
#define MLDSA_GENERATE_KEY_ENTROPY 32

// MLDSA_SIGNATURE_RANDOMIZER_BYTES is the number of bytes of uniformly
// random entropy necessary to generate a signature in randomized mode.
#define MLDSA_SIGNATURE_RANDOMIZER_BYTES 32

// MLDSA_generate_key_external_entropy generates a public/private key pair
// using the given seed, writes the encoded public key to
// |out_encoded_public_key| and sets |out_private_key| to the private key,
// returning 1 on success and 0 on failure. Returns 1 on success and 0 on
// failure.
OPENSSL_EXPORT int MLDSA_generate_key_external_entropy(
    uint8_t out_encoded_public_key[MLDSA_PUBLIC_KEY_BYTES],
    struct MLDSA_private_key *out_private_key,
    const uint8_t entropy[MLDSA_GENERATE_KEY_ENTROPY]);

// MLDSA_sign_deterministic generates a signature for the message |msg| of
// length |msg_len| using |private_key| following the deterministic algorithm,
// and writes the encoded signature to |out_encoded_signature|. Returns 1 on
// success and 0 on failure.
OPENSSL_EXPORT int MLDSA_sign_deterministic(
    uint8_t out_encoded_signature[MLDSA_SIGNATURE_BYTES],
    const struct MLDSA_private_key *private_key, const uint8_t *msg,
    size_t msg_len);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CRYPTO_MLDSA_INTERNAL_H
