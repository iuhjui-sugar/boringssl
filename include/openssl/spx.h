/* Copyright (c) 2023, Google LLC
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
#ifndef OPENSSL_HEADER_SPX_H
#define OPENSSL_HEADER_SPX_H

#include <openssl/base.h>
#include <stdbool.h>

#if defined(__cplusplus)
extern "C" {
#endif

// Number of bytes in the hash output
#define SPX_N 16

// Number of bytes in the public key of SPHINCS+-SHA2-128s
#define SPX_PUBLIC_KEY_BYTES 32

// Number of bytes in the private key of SPHINCS+-SHA2-128s
#define SPX_SECRET_KEY_BYTES 64

// Number of bytes in a signature of SPHINCS+-SHA2-128s
#define SPX_SIGNATURE_BYTES 7856

// Generate a SPHINCS+-SHA2-128s key pair
// Private key: SK.seed || SK.prf || PK.seed || PK.root
// Public key: PK.seed || PK.root
OPENSSL_EXPORT void spx_generate_key(
    uint8_t out_public_key[SPX_PUBLIC_KEY_BYTES],
    uint8_t out_secret_key[SPX_SECRET_KEY_BYTES]);

// Generate a SPHINCS+-SHA2-128s key pair from a 48-byte seed.
// Secret key: SK.seed || SK.prf || PK.seed || PK.root
// Public key: PK.seed || PK.root
OPENSSL_EXPORT void spx_generate_key_from_seed(
    uint8_t out_public_key[SPX_PUBLIC_KEY_BYTES],
    uint8_t out_secret_key[SPX_SECRET_KEY_BYTES],
    const uint8_t seed[3 * SPX_N]);

// Generate a SPHINCS+-SHA2-128s signature.
//
// The randomized flag allows to switch between non-deterministic signing (true)
// or deterministic signing (false).
OPENSSL_EXPORT void spx_sign(uint8_t out_signature[SPX_SIGNATURE_BYTES],
                             const uint8_t secret_key[SPX_SECRET_KEY_BYTES],
                             const uint8_t *msg, size_t msg_len,
                             bool randomized);

// Verify a SPHINCS+-SHA2-128s signature
OPENSSL_EXPORT int spx_verify(const uint8_t signature[SPX_SIGNATURE_BYTES],
                              const uint8_t public_key[SPX_SECRET_KEY_BYTES],
                              const uint8_t *msg, size_t msg_len);

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_SPX_H
