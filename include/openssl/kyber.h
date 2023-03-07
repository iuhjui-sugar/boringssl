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

#ifndef OPENSSL_HEADER_KYBER_H
#define OPENSSL_HEADER_KYBER_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


// KYBER_PUBLIC_KEY_BYTES is the number of bytes of a marshalled public key for
// Kyber768.
#define KYBER_PUBLIC_KEY_BYTES 1184
// KYBER_PRIVATE_KEY_BYTES is the number of bytes of a marshalled private key
// for Kyber768.
#define KYBER_PRIVATE_KEY_BYTES 2400
// KYBER_CIPHERTEXT_BYTES is number of bytes of the Kyber768 ciphertext.
#define KYBER_CIPHERTEXT_BYTES 1088
// KYBER_GENERATE_KEY_ENTROPY is the number of bytes of uniformly random entropy
// necessary to generate a key.
#define KYBER_GENERATE_KEY_ENTROPY 64
// KYBER_ENCAP_ENTROPY is the number of bytes of uniformly random entropy
// necessary to encapsulate a secret. The entropy will be leaked to the
// decapsulating party.
#define KYBER_ENCAP_ENTROPY 32

// KYBER_generate_key is a non-deterministic function that creates a pair of
// Kyber768 keys.
OPENSSL_EXPORT void KYBER_generate_key(
    uint8_t out_public_key[KYBER_PUBLIC_KEY_BYTES],
    uint8_t out_private_key[KYBER_PRIVATE_KEY_BYTES]);

// KYBER_generate_key_external_entropy is a deterministic function to create a
// pair of Kyber768 keys, using the supplied entropy. The entropy needs to be
// uniformly random generated. This function is should only be used for tests,
// regular callers should use the non-deterministic |KYBER_generate_key|
// directly.
OPENSSL_EXPORT void KYBER_generate_key_external_entropy(
    uint8_t out_public_key[KYBER_PUBLIC_KEY_BYTES],
    uint8_t out_private_key[KYBER_PRIVATE_KEY_BYTES],
    const uint8_t entropy[KYBER_GENERATE_KEY_ENTROPY]);

// KYBER_encap is a non-deterministic function to encapsulate
// |out_shared_secret_len| bytes of |out_shared_secret| to |ciphertext|.
OPENSSL_EXPORT void KYBER_encap(
    uint8_t out_ciphertext[KYBER_CIPHERTEXT_BYTES], uint8_t *out_shared_secret,
    size_t out_shared_secret_len,
    const uint8_t public_key[KYBER_PUBLIC_KEY_BYTES]);

// KYBER_encap_external_entropy is a deterministic function to encapsulate
// |out_shared_secret_len| bytes of |out_shared_secret| to |ciphertext|, using
// |KYBER_ENCAP_ENTROPY| bytes of |entropy| for randomization. The
// decapsulating side will be able to recover |entropy| in full. This
// function is should only be used for tests, regular callers should use the
// non-deterministic |KYBER_encap| directly.
OPENSSL_EXPORT void KYBER_encap_external_entropy(
    uint8_t out_ciphertext[KYBER_CIPHERTEXT_BYTES], uint8_t *out_shared_secret,
    size_t out_shared_secret_len,
    const uint8_t public_key[KYBER_PUBLIC_KEY_BYTES],
    const uint8_t entropy[KYBER_ENCAP_ENTROPY]);

// KYBER_decap is a deterministic function to decapsulate |ciphertext| and
// extract |out_shared_secret_len| bytes written to |out_shared_secret|. If a
// malformed ciphertext is passed, the content of |out_shared_secret| will be
// deterministic and unpredictable without access to the private key, without
// |KYBER_decap| failing. Any subsequent symmetric encryption using
// |out_shared_secret| must use an authenticated encryption scheme in order to
// discover the decapsulation failure.
// Decapsulation failure could theoretically also occur randomly with a neglible
// probability of less than 1:2^128.
OPENSSL_EXPORT void KYBER_decap(
    uint8_t *out_shared_secret, size_t out_shared_secret_len,
    const uint8_t ciphertext[KYBER_CIPHERTEXT_BYTES],
    const uint8_t private_key[KYBER_PRIVATE_KEY_BYTES]);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_KYBER_H
