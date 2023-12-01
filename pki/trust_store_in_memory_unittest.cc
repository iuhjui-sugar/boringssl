// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trust_store_in_memory.h"

#include <gtest/gtest.h>
#include "test_helpers.h"

namespace bssl {
namespace {

class TrustStoreInMemoryTest : public testing::Test {
 public:
  void SetUp() override {
    ParsedCertificateList chain;
    ASSERT_TRUE(ReadCertChainFromFile(
        "testdata/verify_certificate_chain_unittest/key-rollover/oldchain.pem",
        &chain));

    ASSERT_EQ(3U, chain.size());
    target_ = chain[0];
    oldintermediate_ = chain[1];
    oldroot_ = chain[2];
    ASSERT_TRUE(target_);
    ASSERT_TRUE(oldintermediate_);
    ASSERT_TRUE(oldroot_);

    ASSERT_TRUE(
        ReadCertChainFromFile("testdata/verify_certificate_chain_unittest/"
                              "key-rollover/longrolloverchain.pem",
                              &chain));

    ASSERT_EQ(5U, chain.size());
    newintermediate_ = chain[1];
    newroot_ = chain[2];
    newrootrollover_ = chain[3];
    ASSERT_TRUE(newintermediate_);
    ASSERT_TRUE(newroot_);
    ASSERT_TRUE(newrootrollover_);
  }

 protected:
  std::shared_ptr<const ParsedCertificate> oldroot_;
  std::shared_ptr<const ParsedCertificate> newroot_;
  std::shared_ptr<const ParsedCertificate> newrootrollover_;

  std::shared_ptr<const ParsedCertificate> target_;
  std::shared_ptr<const ParsedCertificate> oldintermediate_;
  std::shared_ptr<const ParsedCertificate> newintermediate_;
};

TEST_F(TrustStoreInMemoryTest, OneRootTrusted) {
  ParsedCertificateList issuers;

  TrustStoreInMemory in_memory;
  in_memory.AddTrustAnchor(newroot_);

  // newroot_ is trusted.
  CertificateTrust trust = in_memory.GetTrust(newroot_.get());
  EXPECT_EQ(CertificateTrust::ForTrustAnchor().ToDebugString(),
            trust.ToDebugString());

  // oldroot_ is not.
  trust = in_memory.GetTrust(oldroot_.get());
  EXPECT_EQ(CertificateTrust::ForUnspecified().ToDebugString(),
            trust.ToDebugString());
}

TEST_F(TrustStoreInMemoryTest, DistrustBySPKI) {
  ParsedCertificateList issuers;

  TrustStoreInMemory in_memory;
  in_memory.AddDistrustedCertificateBySPKI(newroot_->tbs().spki_tlv.AsString());

  // newroot_ is not trusted.
  CertificateTrust trust = in_memory.GetTrust(newroot_.get());
  EXPECT_EQ(CertificateTrust::ForDistrusted().ToDebugString(),
            trust.ToDebugString());

  // oldroot_ is unspecified.
  trust = in_memory.GetTrust(oldroot_.get());
  EXPECT_EQ(CertificateTrust::ForUnspecified().ToDebugString(),
            trust.ToDebugString());

  // newrootrollover_ is also not trusted because it has the same key.
  trust = in_memory.GetTrust(newrootrollover_.get());
  EXPECT_EQ(CertificateTrust::ForDistrusted().ToDebugString(),
            trust.ToDebugString());
}

TEST_F(TrustStoreInMemoryTest, DistrustBySPKIOverridesTrust) {
  ParsedCertificateList issuers;

  TrustStoreInMemory in_memory;
  in_memory.AddTrustAnchor(newroot_);
  in_memory.AddDistrustedCertificateBySPKI(newroot_->tbs().spki_tlv.AsString());

  // newroot_ is not trusted.
  CertificateTrust trust = in_memory.GetTrust(newroot_.get());
  EXPECT_EQ(CertificateTrust::ForDistrusted().ToDebugString(),
            trust.ToDebugString());
}


}  // namespace
}  // namespace bssl
