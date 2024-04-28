#ifndef __Libcrux_Kem_Kyber_Mlkem768_H
#define __Libcrux_Kem_Kyber_Mlkem768_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <inttypes.h>
#include <stdbool.h>

#include "base.h"

#define MLKEM768_SECRETKEYBYTES 2400
#define MLKEM768_PUBLICKEYBYTES 1184
#define MLKEM768_CIPHERTEXTBYTES 1088
#define MLKEM768_SHAREDSECRETBYTES 32
#define MLKEM768_KEY_GENERATION_RANDOMNESS 64
#define MLKEM768_ENCAPS_RANDOMNESS 32

// Mlkem768_GenerateKeyPair generates a random public/private key pair, writes
// the encoded public key to |out_pk| and sets |out_sk| to the encoded the
// private key.
//
// |out_pk| must point to MLKEM768_PUBLICKEYBYTES bytes of memory
// |out_sk| must point to MLKEM768_SECRETKEYBYTES bytes of memory
OPENSSL_EXPORT void Mlkem768_GenerateKeyPair(
    uint8_t *out_pk, uint8_t *out_sk,
    const uint8_t randomness[MLKEM768_KEY_GENERATION_RANDOMNESS]);


// Mlkem768_Encapsulate encrypts a random shared secret for |pk|, writes the
// ciphertext to |out_ct|, and writes the random shared secret to |out_ss|.
//
// |out_ct| must point to MLKEM768_CIPHERTEXTBYTES bytes of memory
// |out_ss| must point to MLKEM768_SHAREDSECRETBYTES bytes of memory
//
// The function returns one on success or zero on if the public key is invalid.
OPENSSL_EXPORT int Mlkem768_Encapsulate(
    uint8_t *out_ct, uint8_t *out_ss,
    const uint8_t (*pk)[MLKEM768_PUBLICKEYBYTES],
    const uint8_t randomness[MLKEM768_ENCAPS_RANDOMNESS]);

// Mlkem768_Decapsulate decrypts a shared secret from |ct| using |sk| and writes
// it to |out_ss|. If |ct| is invalid, |out_ss| is filled with a key that will
// always be the same for the same |ct| and |sk|, but which appears to be random
// unless one has access to |sk|. These alternatives occur in constant time. Any
// subsequent symmetric encryption using |out_ss| must use an authenticated
// encryption scheme in order to discover the decapsulation failure.
OPENSSL_EXPORT void Mlkem768_Decapsulate(
    uint8_t out_ss[MLKEM768_SHAREDSECRETBYTES],
    const uint8_t (*ct)[MLKEM768_CIPHERTEXTBYTES],
    const uint8_t (*sk)[MLKEM768_SECRETKEYBYTES]);

#if defined(__cplusplus)
}
#endif

#define __Libcrux_Kem_Kyber_Mlkem768_H_DEFINED
#endif
