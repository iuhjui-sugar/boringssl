#include <string.h>

#include "../internal.h"

#include <openssl/mlkem.h>

#include "../../third_party/libcrux/libcrux_mlkem768_portable.h"

#if defined(OPENSSL_X86_64)
#include "../../third_party/libcrux/libcrux_mlkem768_avx2.h"
#endif

void Mlkem768_GenerateKeyPair(
    uint8_t *pk, uint8_t *sk,
    const uint8_t randomness[MLKEM768_KEY_GENERATION_RANDOMNESS]) {
#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    libcrux_ml_kem_mlkem768_MlKem768KeyPair result =
        libcrux_ml_kem_mlkem768_avx2_generate_key_pair((uint8_t *)randomness);
    memcpy(pk, result.pk.value, MLKEM768_PUBLICKEYBYTES);
    memcpy(sk, result.sk.value, MLKEM768_SECRETKEYBYTES);

    return;
  }
#endif  // OPENSSL_X86_64

  libcrux_ml_kem_mlkem768_MlKem768KeyPair result =
      libcrux_ml_kem_mlkem768_portable_generate_key_pair((uint8_t *)randomness);

  memcpy(pk, result.pk.value, MLKEM768_PUBLICKEYBYTES);
  memcpy(sk, result.sk.value, MLKEM768_SECRETKEYBYTES);
}

int Mlkem768_Encapsulate(uint8_t *ct, uint8_t *ss,
                         const uint8_t (*pk)[MLKEM768_PUBLICKEYBYTES],
                         const uint8_t randomness[MLKEM768_ENCAPS_RANDOMNESS]) {
  libcrux_ml_kem_types_MlKemPublicKey____1184size_t pk_value;
  memcpy(pk_value.value, pk, MLKEM768_PUBLICKEYBYTES);
  core_option_Option__libcrux_ml_kem_types_MlKemPublicKey___1184size_t__
      public_key =
          libcrux_ml_kem_mlkem768_portable_validate_public_key(pk_value);
  if (public_key.tag == core_option_None) {
    // The public key is invalid, abort.
    return 0;
  }

#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    K___libcrux_ml_kem_types_MlKemCiphertext___1088size_t___uint8_t_32size_t_
        result = libcrux_ml_kem_mlkem768_avx2_encapsulate(
            &public_key.f0, (uint8_t *)randomness);

    memcpy(ct, result.fst.value, MLKEM768_CIPHERTEXTBYTES);
    memcpy(ss, result.snd, MLKEM768_SHAREDSECRETBYTES);

    return 1;
  }
#endif  // OPENSSL_X86_64

  K___libcrux_ml_kem_types_MlKemCiphertext___1088size_t___uint8_t_32size_t_
      result = libcrux_ml_kem_mlkem768_portable_encapsulate(
          &public_key.f0, (uint8_t *)randomness);

  memcpy(ct, result.fst.value, MLKEM768_CIPHERTEXTBYTES);
  memcpy(ss, result.snd, MLKEM768_SHAREDSECRETBYTES);

  return 1;
}

void Mlkem768_Decapsulate(uint8_t ss[MLKEM768_SHAREDSECRETBYTES],
                          const uint8_t (*ct)[MLKEM768_CIPHERTEXTBYTES],
                          const uint8_t (*sk)[MLKEM768_SECRETKEYBYTES]) {
  libcrux_ml_kem_types_MlKemPrivateKey____2400size_t secret_key;
  memcpy(secret_key.value, sk, MLKEM768_SECRETKEYBYTES);

  libcrux_ml_kem_mlkem768_MlKem768Ciphertext cipher_text;
  memcpy(cipher_text.value, ct, MLKEM768_CIPHERTEXTBYTES);

#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    libcrux_ml_kem_mlkem768_avx2_decapsulate(&secret_key, &cipher_text, ss);

    return;
  }
#endif  // OPENSSL_X86_64

  libcrux_ml_kem_mlkem768_portable_decapsulate(&secret_key, &cipher_text, ss);
}
