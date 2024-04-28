#ifndef __Libcrux_Kem_Kyber_Mlkem768_H
#define __Libcrux_Kem_Kyber_Mlkem768_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <inttypes.h>
#include <stdbool.h>

#define MLKEM768_SECRETKEYBYTES 2400
#define MLKEM768_PUBLICKEYBYTES 1184
#define MLKEM768_CIPHERTEXTBYTES 1088
#define MLKEM768_SHAREDSECRETBYTES 32

void Libcrux_Mlkem768_GenerateKeyPair(uint8_t *pk, uint8_t *sk,
                                      uint8_t randomness[64]);

void Libcrux_Mlkem768_Encapsulate(uint8_t *ct, uint8_t *ss, uint8_t (*pk)[1184],
                                  uint8_t randomness[32]);

void Libcrux_Mlkem768_Decapsulate(uint8_t ss[32U], uint8_t (*ct)[1088U],
                                  uint8_t (*sk)[2400U]);

bool Libcrux_Mlkem768_ValidatePublicKey(uint8_t(pk)[1184]);

#if defined(__cplusplus)
}
#endif

#define __Libcrux_Kem_Kyber_Mlkem768_H_DEFINED
#endif
