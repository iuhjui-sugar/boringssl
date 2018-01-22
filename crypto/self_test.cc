#include <openssl/crypto.h>

#include <gtest/gtest.h>


TEST(SelfTests, KAT) {
  EXPECT_TRUE(BORINGSSL_self_test());
}
