#include <string.h>

#include "../internal.h"

#include <openssl/mlkem.h>

#include "../../third_party/libcrux/libcrux_mlkem768_portable.h"

#if defined(OPENSSL_X86_64)
#include "../../third_party/libcrux/libcrux_mlkem768_avx2.h"
#endif

static inline void portable_keygen(uint8_t randomness[64], uint8_t *pk,
                                   uint8_t *sk) {
  libcrux_ml_kem_mlkem768_MlKem768KeyPair result =
      libcrux_ml_kem_mlkem768_portable_generate_key_pair(randomness);

  memcpy(pk, result.pk.value, MLKEM768_PUBLICKEYBYTES);
  memcpy(sk, result.sk.value, MLKEM768_SECRETKEYBYTES);
}

void Libcrux_Mlkem768_GenerateKeyPair(uint8_t *pk, uint8_t *sk,
                                      uint8_t randomness[64]) {
#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    libcrux_ml_kem_mlkem768_MlKem768KeyPair result =
        libcrux_ml_kem_mlkem768_avx2_generate_key_pair(randomness);
    memcpy(pk, result.pk.value, MLKEM768_PUBLICKEYBYTES);
    memcpy(sk, result.sk.value, MLKEM768_SECRETKEYBYTES);
  } else {
    portable_keygen(randomness, pk, sk);
  }
#else
  portable_keygen(randomness, pk, sk);
#endif  // OPENSSL_X86_64
}

void Libcrux_Mlkem768_Encapsulate(uint8_t *ct, uint8_t *ss, uint8_t (*pk)[1184],
                                  uint8_t randomness[32]) {
#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    K___libcrux_ml_kem_types_MlKemCiphertext___1088size_t___uint8_t_32size_t_
        result = libcrux_ml_kem_mlkem768_avx2_encapsulate(
            (libcrux_ml_kem_types_MlKemPublicKey____1184size_t *)pk,
            randomness);

    memcpy(ct, result.fst.value, MLKEM768_CIPHERTEXTBYTES);
    memcpy(ss, result.snd, MLKEM768_SHAREDSECRETBYTES);
  } else {
    K___libcrux_ml_kem_types_MlKemCiphertext___1088size_t___uint8_t_32size_t_
        result = libcrux_ml_kem_mlkem768_portable_encapsulate(
            (libcrux_ml_kem_types_MlKemPublicKey____1184size_t *)pk,
            randomness);

    memcpy(ct, result.fst.value, MLKEM768_CIPHERTEXTBYTES);
    memcpy(ss, result.snd, MLKEM768_SHAREDSECRETBYTES);
  }
#else
  K___libcrux_ml_kem_types_MlKemCiphertext___1088size_t___uint8_t_32size_t_
      result = libcrux_ml_kem_mlkem768_portable_encapsulate(
          (libcrux_ml_kem_types_MlKemPublicKey____1184size_t *)pk, randomness);

  memcpy(ct, result.fst.value, MLKEM768_CIPHERTEXTBYTES);
  memcpy(ss, result.snd, MLKEM768_SHAREDSECRETBYTES);
#endif  // OPENSSL_X86_64
}

void Libcrux_Mlkem768_Decapsulate(uint8_t ss[32U], uint8_t (*ct)[1088U],
                                  uint8_t (*sk)[2400U]) {
#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    // Alternatives: memcpy or changing the libcrux API to take the pointer.
    libcrux_ml_kem_mlkem768_avx2_decapsulate(
        (libcrux_ml_kem_types_MlKemPrivateKey____2400size_t *)sk,
        (libcrux_ml_kem_mlkem768_MlKem768Ciphertext *)ct, ss);
  } else {
    // Alternatives: memcpy or changing the libcrux API to take the pointer.
    libcrux_ml_kem_mlkem768_portable_decapsulate(
        (libcrux_ml_kem_types_MlKemPrivateKey____2400size_t *)sk,
        (libcrux_ml_kem_mlkem768_MlKem768Ciphertext *)ct, ss);
  }
#else
  // Alternatives: memcpy or changing the libcrux API to take the pointer.
  libcrux_ml_kem_mlkem768_portable_decapsulate(
      (libcrux_ml_kem_types_MlKemPrivateKey____2400size_t *)sk,
      (libcrux_ml_kem_mlkem768_MlKem768Ciphertext *)ct, ss);
#endif  // OPENSSL_X86_64
}

bool Libcrux_Mlkem768_ValidatePublicKey(uint8_t(pk)[1184]) {
  // XXX: The API here probably shouldn't consume.
  libcrux_ml_kem_types_MlKemPublicKey____1184size_t value;
  memcpy(value.value, pk, 1184);
  core_option_Option__libcrux_ml_kem_types_MlKemPublicKey___1184size_t__ ok =
      libcrux_ml_kem_mlkem768_portable_validate_public_key(value);
  return ok.tag == core_option_Some;
}
