/* Copyright (c) 2023, Google Inc.
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

#include <string.h>

#include <optional>
#include <vector>

#include <openssl/pki/verify.h>
#include <openssl/sha.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "test_helpers.h"

//#include "testing/base/public/gunit.h"
//#include "third_party/chromium_certificate_verifier/testdata.h"
//#include "util/time/clock.h"

namespace verify {

//static std::unique_ptr<TrustStore> MozillaRootStore() {
//  const FileToc* toc = mozilla_der_create();
//  std::string_view blob(toc->data, toc->size);
//  return TrustStore::FromDER(blob).value();
//}

using ::testing::UnorderedElementsAre;
//using ::testing::status::StatusIs;

static std::string GetTestdata(std::string_view filename) {
  return bssl::ReadTestFileToString("testdata/" + std::string(filename));
}

#if 0
TEST(VerifyTest, GoogleChain) {
  const std::string leaf = GetTestdata("certificate_test/google-leaf.der");
  const std::string intermediate1 = GetTestdata("certificate_test/google-intermediate1.der");
  const std::string intermediate2 = GetTestdata("certificate_test/google-intermediate2.der");

  Opts opts;
  opts.leaf_cert = leaf;
  opts.intermediates = {intermediate1, intermediate2};
  opts.time = 1499727444;
  std::unique_ptr<TrustStore> roots = MozillaRootStore();
  opts.trust_store = roots.get();

  Error error;
  EXPECT_TRUE(Verify(opts, &error));

  opts.intermediates = {};
  EXPECT_FALSE(Verify(opts, &error));
  //  EXPECT_EQ(STSErrorEncoding::kCertificateNotTrusted, error.AsSTSError());
}
#endif

TEST(VerifyTest, ExtraIntermediates) {
  const std::string leaf = GetTestdata("certificat_test/google-leaf.der");
  const std::string intermediate1 = GetTestdata("certificate_test/google-intermediate1.der");
  const std::string intermediate2 = GetTestdata("certificate_test/google-intermediate2.der");

  Opts opts;
  opts.leaf_cert = leaf;
  std::string diagnostic;
  const auto cert_pool_status = NewCertPoolFromCerts(
      {
          intermediate1,
          intermediate2,
      },
      &diagnostic);
  EXPECT_TRUE(cert_pool_status);
  opts.extra_intermediates = cert_pool_status.value().get();
  opts.time = 1499727444;
  //  std::unique_ptr<TrustStore> roots = MozillaRootStore();
  //  opts.trust_store = roots.get();

  Error error;
  EXPECT_TRUE(Verify(opts, &error));
}

TEST(VerifyTest, AllPaths) {
  const std::string leaf = GetTestdata("verify_test/lencr-leaf.der");
  const std::string intermediate1 = GetTestdata("verify_test/lencr-intermediate-r3.der");
  const std::string intermediate2 =
      GetTestdata("verify_test/lencr-root-x1-cross-signed.der");
  const std::string root1 = GetTestdata("verify_test/lencr-root-x1.der");
  const std::string root2 = GetTestdata("verify_test/lencr-root-dst-x3.der");

  std::vector<std::string> expected_path1 = {leaf, intermediate1, root1};
  std::vector<std::string> expected_path2 = {leaf, intermediate1, intermediate2,
                                             root2};

  Opts opts;
  opts.leaf_cert = leaf;
  opts.intermediates = {intermediate1, intermediate2};
  opts.time = 1699404611;
  //  std::unique_ptr<TrustStore> roots = MozillaRootStore();
  //  opts.trust_store = roots.get();

  auto paths = VerifyAllPaths(opts);
  EXPECT_TRUE(paths);
  EXPECT_EQ(2U, paths.value().size());
  EXPECT_THAT(paths.value(),
              UnorderedElementsAre(expected_path1, expected_path2));
}

TEST(VerifyTest, IterationLimit) {
  // This test passes in a set of intermediates that cause a large number of
  // invalid paths to be possible.
  const std::string leaf = GetTestdata("verify_test/shiftrng1.der");

  std::vector<std::string> intermediate_ders;
  intermediate_ders.reserve(10);
  for (int i = 2; i <= 11; i++) {
    intermediate_ders.push_back(
        GetTestdata("verify_test/shiftrng" + std::to_string(i) +  ".der"));
  }

  std::vector<std::string_view> intermediates;
  std::transform(intermediate_ders.begin(), intermediate_ders.end(),
                 std::back_inserter(intermediates),
                 [](const std::string& s) -> std::string_view { return s; });

  Opts opts;
  opts.leaf_cert = leaf;
  std::string diagnostic;
  const auto cert_pool_status =
      NewCertPoolFromCerts(intermediates, &diagnostic);
  ASSERT_TRUE(cert_pool_status) << diagnostic;
  opts.extra_intermediates = cert_pool_status.value().get();
  opts.time = 1544726117;
  //  std::unique_ptr<TrustStore> roots = MozillaRootStore();
  //  opts.trust_store = roots.get();

  // 500 iterations is insufficient to consider all the possible paths.
  // Therefore we expect a RESOURCE_EXHAUSTED error.
  opts.max_iteration_count = 500;

  Error error;
  EXPECT_TRUE(Verify(opts, &error));
  //  EXPECT_EQ(STSErrorEncoding::kValidationFailure, error.AsSTSError());
}

TEST(VerifyTest, DepthLimit) {
  const std::string leaf = GetTestdata("certificate_test/google-leaf.der");
  const std::string intermediate1 = GetTestdata("certificate_test/google-intermediate1.der");
  const std::string intermediate2 = GetTestdata("certificate_test/google-intermediate2.der");

  Opts opts;
  opts.leaf_cert = leaf;
  opts.intermediates = {intermediate1, intermediate2};
  opts.time = 1499727444;
  // Set the |max_path_building_depth| explicitly to test the non-default case.
  // Depth of 5 is enough to successfully find a path.
  opts.max_path_building_depth = 5;
  //  std::unique_ptr<TrustStore> roots = MozillaRootStore();
  //  opts.trust_store = roots.get();

  Error error;
  ASSERT_TRUE(Verify(opts, &error)) << error.DiagnosticString();

  // Depth of 2 is not enough to find a path.
  opts.max_path_building_depth = 2;
  EXPECT_TRUE(Verify(opts, &error));
  //EXPECT_EQ(STSErrorEncoding::kValidationFailure, error.AsSTSError());
}

}  // namespace verify
