/* Copyright (c) 2020, Google Inc.
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

#ifndef OPENSSL_HEADER_CRYPTO_HPKE_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_HPKE_INTERNAL_H

#include <openssl/aead.h>
#include <openssl/base.h>
#include <openssl/curve25519.h>

#if defined(__cplusplus)
extern "C" {
#endif

#include "../crypto/evp/internal.h"

// https://www.ietf.org/id/draft-irtf-cfrg-hpke-04.html
//
// HPKE primitives:
//   * KEM
//   * KDF
//   * AEAD
//
// KEM {
//   GenerateKeyPair() -> (sk, pk)
//   Marshal(pk) -> FixedLen<byte, N>
//   Unmarshal(FixedLen<byte, N>) -> pk
//   Encap(pk) -> ...
//     Generate an ephemeral, fixed-length symmetric key and a fixed-length
//     encapsulation of that key that can be decapsulated by the holder of the
//     private key corresponding to pk
//   Decap(enc, sk) -> symmetric_key
//   ...
// }
//
// KDF {
//   Extract(salt, IKM) -> FixedLen<byte, Nh()>
//   Expand(PRK, info, L) -> FixedLen<byte, L>
//   Nh() -> size
// }
//
// AEAD is already implemented in boringssl.
//
// Design considerations:
//
//   To keep things simple (boring?), I'd like to only support DH/X25519/SHA256.
//   This enables us to skip a whole layer of pseudo-C++ for the HPKE API. I
//   don't think this choice is going to lock us into the current design. Since
//   it will only be an internal API for ECHO (for now), we can add an
//   abstraction layer in the future, if we choose to expose an HPKE API.

#define EVP_HPKE_MAX_PK_LEN X25519_PUBLIC_VALUE_LEN
#define EVP_HPKE_MAX_SK_LEN X25519_PRIVATE_KEY_LEN
#define EVP_HPKE_MAX_SHARED_KEY_LEN X25519_SHARED_KEY_LEN

typedef struct evp_hpke_ctx_st {
  const EVP_MD *kem_hkdf_md;
  const EVP_MD *hkdf_md;
  EVP_AEAD_CTX aead;

  // Context for encryption and decryption.
  // https://www.ietf.org/id/draft-irtf-cfrg-hpke-04.html#section-5.2
  uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH];
  uint8_t exporter_secret[EVP_MAX_MD_SIZE];
  uint64_t seq;
} EVP_HPKE_CTX;

OPENSSL_EXPORT void EVP_HPKE_CTX_init(EVP_HPKE_CTX *ctx);
OPENSSL_EXPORT void EVP_HPKE_CTX_cleanup(EVP_HPKE_CTX *ctx);


// Encryption to a Public Key.
// https://www.ietf.org/id/draft-irtf-cfrg-hpke-04.html#section-5.1.1
//
// For all EVP_HPKE_CTX_setup_base* functions:
//   * The |hpke| parameter must be non-NULL and already initialized.
//   * The |info| parameter is optional. When not NULL, the function will use
//     |info_len| bytes to influence key generation.


// EVP_HPKE_CTX_setup_base_x25519_s sets up |hpke| as a sender context that can
// encrypt for the private key corresponding to |peer_public_value| (the
// recipient's public key). It returns one on success, and zero otherwise.
//
// This function writes the encapsulation of |peer_public_value| into the
// |out_enc| buffer, which must contain at least |X25519_PUBLIC_VALUE_LEN|
// bytes.
OPENSSL_EXPORT int EVP_HPKE_CTX_setup_base_x25519_s(
    EVP_HPKE_CTX *hpke, uint8_t *out_enc,
    const uint8_t peer_public_value[X25519_PUBLIC_VALUE_LEN],
    const uint8_t *info, size_t info_len);

// EVP_HPKE_CTX_setup_base_x25519_r sets up |hpke| as a recipient context that
// can decrypt messages using the symmetric key |enc| and the recipient's
// private key |private_key|. It returns one on success, and zero otherwise.
OPENSSL_EXPORT int EVP_HPKE_CTX_setup_base_x25519_r(
    EVP_HPKE_CTX *hpke, const uint8_t enc[X25519_PUBLIC_VALUE_LEN],
    const uint8_t private_key[X25519_PRIVATE_KEY_LEN], const uint8_t *info,
    size_t info_len);

// EVP_HPKE_CTX_open uses the HPKE context |hpke| to decrypt |ct_len| bytes of
// ciphertext |ct|. It returns one on success, and zero otherwise.
//
// At most, |ct_len| decrypted bytes are written to |out|. On successful return,
// |*out_len| is set to the actual number of bytes written.
//
// To ensure success, |max_out_len| should not be less than |ct_len|.
OPENSSL_EXPORT int EVP_HPKE_CTX_open(EVP_HPKE_CTX *hpke, const uint8_t *ct, size_t ct_len,
                      uint8_t *out, size_t *out_len, size_t max_out_len);

// EVP_HPKE_CTX_seal(...);
// EVP_HPKE_CTX_export(...);

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CRYPTO_HPKE_INTERNAL_H
