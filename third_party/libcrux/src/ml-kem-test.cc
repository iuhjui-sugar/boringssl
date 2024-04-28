#include <gtest/gtest.h>
#include <fstream>

#include "Libcrux_Kem_ML_KEM768.h"

using namespace std;

TEST(MLKEM768Test, ConsistencyTest) {
  uint8_t randomness[64] = {0x37};
  uint8_t publicKey[KYBER768_PUBLICKEYBYTES];
  uint8_t secretKey[KYBER768_SECRETKEYBYTES];

  Libcrux_Kyber768_GenerateKeyPair(publicKey, secretKey, randomness);

  uint8_t ciphertext[KYBER768_CIPHERTEXTBYTES];
  uint8_t sharedSecret[KYBER768_SHAREDSECRETBYTES];

  uint8_t encap_randomness[64] = {0x38};
  Libcrux_Kyber768_Encapsulate(ciphertext, sharedSecret, &publicKey,
                               encap_randomness);

  uint8_t sharedSecret2[KYBER768_SHAREDSECRETBYTES];
  Libcrux_Kyber768_Decapsulate(sharedSecret2, &ciphertext, &secretKey);

  EXPECT_EQ(0, memcmp(sharedSecret, sharedSecret2, KYBER768_SHAREDSECRETBYTES));
}
