#ifndef THIRD_PARTY_CHROMIUM_CERTIFICATE_VERIFIER_FILLINS_CERT_TEST_UTIL_H_
#define THIRD_PARTY_CHROMIUM_CERTIFICATE_VERIFIER_FILLINS_CERT_TEST_UTIL_H_

#include <memory>  // for shared_ptr
#include <string>  // for string

#include "third_party/chromium_certificate_verifier/cert/x509_certificate.h"
#include "third_party/openssl/pool.h"

namespace bssl {

// Imports all of the certificates in |cert_file|, a file in |certs_dir|, into a
// CertificateList.  |format| is one of the |FORMAT_*| constants in the
// |X509Certificate| class, though in practice, only PEM works.
//
// Any errors in file I/O crash the program.  If the file can be read, all
// PEM-encoded certificates that can be found will be consumed.  The program
// will crash if none can be found.  The certificates are not required to be
// valid: only the PEM need be valid.
//
// This may differ from the behavior of the Chromium function of the same name.
CertificateList CreateCertificateListFromFile(const std::string& certs_dir,
                                              const std::string& cert_file,
                                              int format);

// Imports all of the certificates in |cert_file|, a file in |certs_dir|, into
// a new X509Certificate. The first certificate in the chain will be used for
// the returned cert, with any additional certificates configured as
// intermediate certificates.
//
// Any errors in file I/O crash the program.  If the file can be read, all
// PEM-encoded certificates that can be found will be consumed.  The program
// will crash if none can be found.  The certificates are not required to be
// valid: only the PEM need be valid.
//
// This may differ from the behavior of the Chromium function of the same name.
std::shared_ptr<X509Certificate> CreateCertificateChainFromFile(
    const std::string& certs_dir, const std::string& cert_file, int format);

namespace x509_util {

// CreateSelfSignedCert creates a self-signed certificate, using a randomly
// generated private key and SHA-256.  This differs slightly from upstream,
// which allows the caller to specify a few more options.
bool CreateSelfSignedCert(const std::string& subject, uint32_t serial_number,
                          absl::Time not_valid_before,
                          absl::Time not_valid_after, std::string* der_encoded);

}  // namespace x509_util

}  // namespace bssl

#endif  // THIRD_PARTY_CHROMIUM_CERTIFICATE_VERIFIER_FILLINS_CERT_TEST_UTIL_H_
