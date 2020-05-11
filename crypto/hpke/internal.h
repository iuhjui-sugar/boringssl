// TODO(dmcardle) add boilerplate

#ifndef OPENSSL_HEADER_CRYPTO_HPKE_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_HPKE_INTERNAL_H

#include <openssl/aead.h>
#include <openssl/base.h>
#include <openssl/curve25519.h>
#include <openssl/ssl.h> // Is this okay? I need SSL_CURVE_X25519.

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

const size_t EVP_HPKE_MAX_PK_LEN = X25519_PUBLIC_VALUE_LEN;
const size_t EVP_HPKE_MAX_SK_LEN = X25519_PRIVATE_KEY_LEN;
const size_t EVP_HPKE_MAX_SHARED_KEY_LEN = X25519_SHARED_KEY_LEN;

typedef enum evp_hpke_kem_scheme_id {
  EVP_HPKE_KEM_SCHEME_ID_DHKEM_X25519 = 0x0020,
} evp_hpke_kem_scheme_id;

typedef enum evp_hpke_mode {
  EVP_HPKE_MODE_BASE = 0, // We only support |HPKE_MODE_BASE|.
  EVP_HPKE_MODE_PSK = 1,
  EVP_HPKE_MODE_AUTH = 2,
  EVP_HPKE_MODE_AUTH_PSK = 3,
} evp_hpke_mode;

// Our KEM is only suitable for |HPKE_KEM_SCHEME_ID_DHKEM_X25519|.
typedef struct evp_hpke_kem {
  uint16_t kem_group;
  const EVP_MD *kem_hkdf_md;
  uint8_t kem_sk_e[X25519_PRIVATE_KEY_LEN];
} evp_hpke_kem;

void EVP_HPKE_KEM_init(evp_hpke_kem *kem);
void EVP_HPKE_KEM_cleanup(evp_hpke_kem *kem);

typedef struct evp_hpke_ctx_st {
  evp_hpke_kem kem;
  const EVP_MD *hkdf_md;
  // AEAD:
  uint8_t aead_key[EVP_AEAD_MAX_KEY_LENGTH];
  EVP_AEAD_CTX aead;

  // Context for encryption and decryption.
  // https://www.ietf.org/id/draft-irtf-cfrg-hpke-04.html#section-5.2
  uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH];
  uint8_t exporter_secret[EVP_HPKE_MAX_SK_LEN];
  uint64_t seq;
} evp_hpke_ctx;

int EVP_HPKE_CTX_init(evp_hpke_ctx *ctx);
void EVP_HPKE_CTX_cleanup(evp_hpke_ctx *ctx);

// EVP_HPKE_KEM_generate_key generates a keypair using |kem|. It returns one on
// success, and zero otherwise.
//
// The public key is written to |out_pk| and the private key is written to
// |out_sk|.
//
// |out_pk| must have space for |EVP_HPKE_MAX_PK_LEN| bytes.
// |out_sk| must have space for |EVP_HPKE_MAX_SK_LEN| bytes.
int EVP_HPKE_KEM_generate_key(const evp_hpke_kem *kem, uint8_t *out_pk,
                              size_t *out_pk_len, uint8_t *out_sk,
                              size_t *out_sk_len);

// https://www.ietf.org/id/draft-irtf-cfrg-hpke-04.html#section-5.1.1

// EVP_HPKE_CTX_setup_base_curve25519_s sets up |hpke| as a sender context that
// can encrypt for the private key corresponding to |pkR|. It returns one on
// success, and zero otherwise.
//
// Precondition: |hpke| should have already been initialized with
// |EVP_HPKE_CTX_init|.
int EVP_HPKE_CTX_setup_base_curve25519_s(evp_hpke_ctx *hpke,
                                         const EVP_PKEY_CTX *pkR_ctx,
                                         const EVP_PKEY *pkR,
                                         const uint8_t *info, size_t info_len);

// EVP_HPKE_CTX_setup_base_curve25519_r sets up |hpke| as a recipient context
// that can encrypt for the private key |skR|. It returns one on success, and
// zero otherwise.
//
// Precondition: |hpke| should have already been initialized with
// |EVP_HPKE_CTX_init|.
int EVP_HPKE_CTX_setup_base_curve25519_r(evp_hpke_ctx *hpke, const uint8_t *enc,
                                         size_t enc_len,
                                         const EVP_PKEY_CTX *skR_ctx,
                                         const EVP_PKEY *skR,
                                         const uint8_t *info, size_t info_len);

// EVP_HPKE_CTX_open uses the HPKE context |hpke| to decrypt |ct_len| bytes of
// ciphertext |ct|. It returns one on success, and zero otherwise.
//
// At most, |ct_len| decrypted bytes are written to |out|. On successful return,
// |*out_len| is set to the actual number of bytes written.
//
// To ensure success, |max_out_len| should not be less than |ct_len|.
int EVP_HPKE_CTX_open(evp_hpke_ctx *hpke, uint8_t *ct, size_t ct_len,
                      uint8_t *out, size_t *out_len, size_t max_out_len);

// EVP_HPKE_CTX_seal(...);
// EVP_HPKE_CTX_export(...);

#endif  // OPENSSL_HEADER_CRYPTO_HPKE_INTERNAL_H
