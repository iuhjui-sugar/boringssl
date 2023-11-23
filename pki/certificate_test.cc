#include <optional>
#include <string>
#include <string_view>

#include <boringssl/certificate.h>
#include <gmock/gmock.h>

#include "string_util.h"
#include "test_helpers.h"

//#include "testing/base/public/gmock_utils/status-matchers.h"
//#include "testing/base/public/gunit.h"
//#include "third_party/absl/strings/escaping.h"
//#include "third_party/absl/time/time.h"
//#include "third_party/chromium_certificate_verifier/testdata.h"

TEST(CertificateTest, FromPEM) {
  std::optional<std::unique_ptr<bssl::Certificate>> cert(
      bssl::Certificate::FromPEM("nonsense"));
  EXPECT_FALSE(cert.has_value());

  cert = bssl::Certificate::FromPEM(
      bssl::ReadTestFileToString("testdata/certificate_test/self-issued.pem"));
  EXPECT_TRUE(cert);
}

TEST(CertificateTest, IsSelfIssued) {
  const std::string leaf =
      bssl::ReadTestFileToString("testdata/certificate_test/google-leaf.der");
  std::optional<std::unique_ptr<bssl::Certificate>> leaf_cert(
      bssl::Certificate::FromDER(leaf));
  EXPECT_TRUE(leaf_cert);
  EXPECT_FALSE(leaf_cert.value()->IsSelfIssued());

  const std::string self_issued =
      bssl::ReadTestFileToString("testdata/certificate_test/self-issued.pem");
  std::optional<std::unique_ptr<bssl::Certificate>> self_issued_cert(
      bssl::Certificate::FromPEM(self_issued));
  EXPECT_TRUE(self_issued_cert);
  EXPECT_TRUE(self_issued_cert.value()->IsSelfIssued());
}

TEST(CertificateTest, Validity) {
  const std::string leaf =
      bssl::ReadTestFileToString("testdata/certificate_test/google-leaf.der");
  std::optional<std::unique_ptr<bssl::Certificate>> cert(
      bssl::Certificate::FromDER(leaf));
  EXPECT_TRUE(cert);

  bssl::Certificate::Validity validity = cert.value()->GetValidity();
  EXPECT_EQ(validity.not_before, 1498644466);
  EXPECT_EQ(validity.not_after, 1505899620);
}

TEST(CertificateTest, SerialNumber) {
  const std::string leaf =
      bssl::ReadTestFileToString("testdata/certificate_test/google-leaf.der");
  std::optional<std::unique_ptr<bssl::Certificate>> cert(
      bssl::Certificate::FromDER(leaf));
  EXPECT_TRUE(cert);
  EXPECT_STREQ(
      (bssl::string_util::HexEncode(cert.value()->GetSerialNumber().data(),
                                    cert.value()->GetSerialNumber().size()))
          .c_str(),
      "0118F044A8F31892");
}
