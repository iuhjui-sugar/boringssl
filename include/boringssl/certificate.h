#ifndef BSSL_CERTIFICATE_H_
#define BSSL_CERTIFICATE_H_

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace bssl {

struct CertificateInternals;

// Certificate represents a parsed X.509 certificate. It includes accessors for
// the various things that one might want to extract from a certificate,
// although it's still growing as needs arise.
class Certificate {
 public:
  Certificate(Certificate&& other);
  Certificate(const Certificate& other) = delete;
  ~Certificate();
  Certificate& operator=(const Certificate& other) = delete;

  // FromDER returns a certificate from an DER-encoded X.509 object.
  static std::optional<std::unique_ptr<Certificate>> FromDER(
      std::string_view der);

  // FromPEM returns a certificate from the first CERTIFICATE PEM block in
  // `pem`.
  static std::optional<std::unique_ptr<Certificate>> FromPEM(
      std::string_view pem);

  // IsSelfIssued returns true if the certificate is "self-issued" per RFC 5280
  // section 6.1. I.e. that the subject and issuer names are equal after
  // canonicalization. This is often called "self-signed".
  //
  // Note that other contexts may define "self-signed" differently. OpenSSL, for
  // example, also considers matching authority and subject key IDs to make a
  // certificate self-signed. Go compares the names, but without
  // canonicalization. No doubt some actually check that the signature is valid.
  bool IsSelfIssued() const;

  // Validity specifies the temporal validity of a cerificate, expressed in
  // POSIX time values of seconds since the POSIX epoch. The certificate is
  // valid at instants t, where not_before <= t <= not_after.
  struct Validity {
    int64_t not_before;
    int64_t not_after;
  };

  Validity GetValidity() const;

  // The binary, big-endian, DER representation of the certificate serial
  // number. It may include a leading 00 byte.
  std::vector<uint8_t> GetSerialNumber() const;

 private:
  explicit Certificate(std::unique_ptr<CertificateInternals> internals);

  std::unique_ptr<CertificateInternals> internals_;
};

}  // namespace verify

#endif  // BSSL_CERTIFICATE_H_
