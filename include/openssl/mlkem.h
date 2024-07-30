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

#ifndef OPENSSL_HEADER_MLKEM_H
#define OPENSSL_HEADER_MLKEM_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


// ML-KEM-768.
//
// This implements the Module-Lattice-Based Key-Encapsulation Mechanism from
// https://csrc.nist.gov/pubs/fips/204/final


// MLKEM_public_key contains a ML-KEM-768 public key. The contents of this
// object should never leave the address space since the format is unstable.
struct MLKEM_public_key {
  union {
    uint8_t bytes[512 * (3 + 9) + 32 + 32];
    uint16_t alignment;
  } opaque;
};

// MLKEM_private_key contains a ML-KEM-768 private key. The contents of this
// object should never leave the address space since the format is unstable.
struct MLKEM_private_key {
  union {
    uint8_t bytes[512 * (3 + 3 + 9) + 32 + 32 + 32];
    uint16_t alignment;
  } opaque;
};

// MLKEM_PUBLIC_KEY_BYTES is the number of bytes in an encoded ML-KEM-768 public
// key.
#define MLKEM_PUBLIC_KEY_BYTES 1184

// MLKEM_SHARED_SECRET_BYTES is the number of bytes in the ML-KEM-768 shared
// secret.
#define MLKEM_SHARED_SECRET_BYTES 32

// MLKEM_SEED_BYTES is the number of bytes in an ML-KEM seed.
#define MLKEM_SEED_BYTES 64

// MLKEM_generate_key generates a random public/private key pair, writes the
// encoded public key to |out_encoded_public_key| and sets |out_private_key| to
// the private key.
OPENSSL_EXPORT void MLKEM_generate_key(
    uint8_t out_encoded_public_key[MLKEM_PUBLIC_KEY_BYTES],
    uint8_t optional_out_seed[MLKEM_SEED_BYTES],
    struct MLKEM_private_key *out_private_key);

// MLKEM_private_key_from_seed generates a private key from a seed that was
// generated by `MLKEM_generate_key`.
OPENSSL_EXPORT void MLKEM_private_key_from_seed(
    struct MLKEM_private_key *out_private_key,
    const uint8_t seed[MLKEM_SEED_BYTES]);

// MLKEM_public_from_private sets |*out_public_key| to the public key that
// corresponds to |private_key|. (This is faster than parsing the output of
// |MLKEM_generate_key| if, for some reason, you need to encapsulate to a key
// that was just generated.)
OPENSSL_EXPORT void MLKEM_public_from_private(
    struct MLKEM_public_key *out_public_key,
    const struct MLKEM_private_key *private_key);

// MLKEM_CIPHERTEXT_BYTES is number of bytes in the ML-KEM-768 ciphertext.
#define MLKEM_CIPHERTEXT_BYTES 1088

// MLKEM_encap encrypts a random shared secret for |public_key|, writes the
// ciphertext to |out_ciphertext|, and writes the random shared secret to
// |out_shared_secret|.
OPENSSL_EXPORT void MLKEM_encap(
    uint8_t out_ciphertext[MLKEM_CIPHERTEXT_BYTES],
    uint8_t out_shared_secret[MLKEM_SHARED_SECRET_BYTES],
    const struct MLKEM_public_key *public_key);

// MLKEM_decap decrypts a shared secret from |ciphertext| using |private_key|
// and writes it to |out_shared_secret|. If |ciphertext| is invalid,
// |out_shared_secret| is filled with a key that will always be the same for the
// same |ciphertext| and |private_key|, but which appears to be random unless
// one has access to |private_key|. These alternatives occur in constant time.
// Any subsequent symmetric encryption using |out_shared_secret| must use an
// authenticated encryption scheme in order to discover the decapsulation
// failure.
OPENSSL_EXPORT void MLKEM_decap(
    uint8_t out_shared_secret[MLKEM_SHARED_SECRET_BYTES],
    const uint8_t ciphertext[MLKEM_CIPHERTEXT_BYTES],
    const struct MLKEM_private_key *private_key);


// Serialisation of keys.

// MLKEM_marshal_public_key serializes |public_key| to |out| in the standard
// format for ML-KEM-768 public keys. It returns one on success or zero on
// allocation error.
OPENSSL_EXPORT int MLKEM_marshal_public_key(
    CBB *out, const struct MLKEM_public_key *public_key);

// MLKEM_parse_public_key parses a public key, in the format generated by
// |MLKEM_marshal_public_key|, from |in| and writes the result to
// |out_public_key|. It returns one on success or zero on parse error or if
// there are trailing bytes in |in|.
OPENSSL_EXPORT int MLKEM_parse_public_key(
    struct MLKEM_public_key *out_public_key, CBS *in);

// MLKEM_marshal_private_key serializes |private_key| to |out| in the standard
// format for ML-KEM-768 private keys. It returns one on success or zero on
// allocation error.
OPENSSL_EXPORT int MLKEM_marshal_private_key(
    CBB *out, const struct MLKEM_private_key *private_key);

// MLKEM_PRIVATE_KEY_BYTES is the length of the data produced by
// |MLKEM_marshal_private_key|.
#define MLKEM_PRIVATE_KEY_BYTES 2400

// MLKEM_parse_private_key parses a private key, in the format generated by
// |MLKEM_marshal_private_key|, from |in| and writes the result to
// |out_private_key|. It returns one on success or zero on parse error or if
// there are trailing bytes in |in|.
OPENSSL_EXPORT int MLKEM_parse_private_key(
    struct MLKEM_private_key *out_private_key, CBS *in);


// ML-KEM-1024
//
// ML-KEM-1024 also exists. You should prefer ML-KEM-768 wherever possible.

// MLKEM1024_public_key contains an ML-KEM-1024 public key. The contents of this
// object should never leave the address space since the format is unstable.
struct MLKEM1024_public_key {
  union {
    uint8_t bytes[512 * (4 + 16) + 32 + 32];
    uint16_t alignment;
  } opaque;
};

// MLKEM1024_private_key contains a ML-KEM-1024 private key. The contents of
// this object should never leave the address space since the format is
// unstable.
struct MLKEM1024_private_key {
  union {
    uint8_t bytes[512 * (4 + 4 + 16) + 32 + 32 + 32];
    uint16_t alignment;
  } opaque;
};

// MLKEM1024_PUBLIC_KEY_BYTES is the number of bytes in an encoded ML-KEM-1024
// public key.
#define MLKEM1024_PUBLIC_KEY_BYTES 1568

// MLKEM1024_SHARED_SECRET_BYTES is the number of bytes in the ML-KEM-1024
// shared secret.
#define MLKEM1024_SHARED_SECRET_BYTES 32

// MLKEM1024_generate_key generates a random public/private key pair, writes the
// encoded public key to |out_encoded_public_key| and sets |out_private_key| to
// the private key.
OPENSSL_EXPORT void MLKEM1024_generate_key(
    uint8_t out_encoded_public_key[MLKEM1024_PUBLIC_KEY_BYTES],
    uint8_t optional_out_seed[MLKEM_SEED_BYTES],
    struct MLKEM1024_private_key *out_private_key);

// MLKEM1024_private_key_from_seed generates a private key from a seed that was
// generated by `MLKEM1024_generate_key`.
OPENSSL_EXPORT void MLKEM1024_private_key_from_seed(
    struct MLKEM1024_private_key *out_private_key,
    const uint8_t seed[MLKEM_SEED_BYTES]);

// MLKEM1024_public_from_private sets |*out_public_key| to the public key that
// corresponds to |private_key|. (This is faster than parsing the output of
// |MLKEM1024_generate_key| if, for some reason, you need to encapsulate to a
// key that was just generated.)
OPENSSL_EXPORT void MLKEM1024_public_from_private(
    struct MLKEM1024_public_key *out_public_key,
    const struct MLKEM1024_private_key *private_key);

// MLKEM1024_CIPHERTEXT_BYTES is number of bytes in the ML-KEM-1024 ciphertext.
#define MLKEM1024_CIPHERTEXT_BYTES 1568

// MLKEM1024_encap encrypts a random shared secret for |public_key|, writes the
// ciphertext to |out_ciphertext|, and writes the random shared secret to
// |out_shared_secret|.
OPENSSL_EXPORT void MLKEM1024_encap(
    uint8_t out_ciphertext[MLKEM1024_CIPHERTEXT_BYTES],
    uint8_t out_shared_secret[MLKEM_SHARED_SECRET_BYTES],
    const struct MLKEM1024_public_key *public_key);

// MLKEM1024_decap decrypts a shared secret from |ciphertext| using
// |private_key| and writes it to |out_shared_secret|. If |ciphertext| is
// invalid, |out_shared_secret| is filled with a key that will always be the
// same for the same |ciphertext| and |private_key|, but which appears to be
// random unless one has access to |private_key|. These alternatives occur in
// constant time. Any subsequent symmetric encryption using |out_shared_secret|
// must use an authenticated encryption scheme in order to discover the
// decapsulation failure.
OPENSSL_EXPORT void MLKEM1024_decap(
    uint8_t out_shared_secret[MLKEM_SHARED_SECRET_BYTES],
    const uint8_t ciphertext[MLKEM1024_CIPHERTEXT_BYTES],
    const struct MLKEM1024_private_key *private_key);


// Serialisation of ML-KEM-1024 keys.

// MLKEM1024_marshal_public_key serializes |public_key| to |out| in the standard
// format for ML-KEM-1024 public keys. It returns one on success or zero on
// allocation error.
OPENSSL_EXPORT int MLKEM1024_marshal_public_key(
    CBB *out, const struct MLKEM1024_public_key *public_key);

// MLKEM1024_parse_public_key parses a public key, in the format generated by
// |MLKEM1024_marshal_public_key|, from |in| and writes the result to
// |out_public_key|. It returns one on success or zero on parse error or if
// there are trailing bytes in |in|.
OPENSSL_EXPORT int MLKEM1024_parse_public_key(
    struct MLKEM1024_public_key *out_public_key, CBS *in);

// MLKEM1024_marshal_private_key serializes |private_key| to |out| in the
// standard format for ML-KEM-1024 private keys. It returns one on success or
// zero on allocation error.
OPENSSL_EXPORT int MLKEM1024_marshal_private_key(
    CBB *out, const struct MLKEM1024_private_key *private_key);

// MLKEM1024_PRIVATE_KEY_BYTES is the length of the data produced by
// |MLKEM1024_marshal_private_key|.
#define MLKEM1024_PRIVATE_KEY_BYTES 3168

// MLKEM1024_parse_private_key parses a private key, in the format generated by
// |MLKEM1024_marshal_private_key|, from |in| and writes the result to
// |out_private_key|. It returns one on success or zero on parse error or if
// there are trailing bytes in |in|.
OPENSSL_EXPORT int MLKEM1024_parse_private_key(
    struct MLKEM1024_private_key *out_private_key, CBS *in);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_MLKEM_H
