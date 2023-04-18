#include "third_party/chromium_certificate_verifier/fillins/cert_test_util.h"

#include <stddef.h>  // for size_t

#include <algorithm>  // for move
#include <vector>     // for vector

#include "base/logging.h"       // for Check_EQImpl
#include "file/base/helpers.h"  // for GetContents
#include "file/base/options.h"  // for Defaults
#include "file/base/path.h"     // for JoinPath
#include "third_party/absl/strings/match.h"
#include "third_party/absl/time/time.h"
#include "third_party/absl/types/span.h"
#include "third_party/chromium_certificate_verifier/cert/x509_certificate.h"
#include "third_party/chromium_certificate_verifier/der/encode_values.h"
#include "third_party/chromium_certificate_verifier/der/parse_values.h"
#include "third_party/openssl/base.h"
#include "third_party/openssl/bn.h"
#include "third_party/openssl/bytestring.h"
#include "third_party/openssl/evp.h"
#include "third_party/openssl/mem.h"
#include "third_party/openssl/rsa.h"
#include "util/task/status.h"  // for Status, QCHECK_OK, etc

namespace bssl {

CertificateList CreateCertificateListFromFile(const std::string& certs_dir,
                                              const std::string& cert_file,
                                              int format) {
  std::string cert_path = file::JoinPath(certs_dir, cert_file);
  std::string cert_data;
  QCHECK_OK(file::GetContents(cert_path, &cert_data, file::Defaults()));
  return X509Certificate::CreateCertificateListFromBytes(
      absl::MakeSpan(reinterpret_cast<const uint8_t*>(cert_data.data()),
                     cert_data.size()),
      format);
}

std::shared_ptr<X509Certificate> CreateCertificateChainFromFile(
    const std::string& certs_dir, const std::string& cert_file, int format) {
  CertificateList certs =
      CreateCertificateListFromFile(certs_dir, cert_file, format);
  if (certs.empty()) return nullptr;

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  for (size_t i = 1; i < certs.size(); ++i)
    intermediates.push_back(bssl::UpRef(certs[i]->cert_buffer()));

  std::shared_ptr<X509Certificate> result(X509Certificate::CreateFromBuffer(
      bssl::UpRef(certs[0]->cert_buffer()), std::move(intermediates)));
  return result;
}

// Adds an X.509 Name with the specified common name to |cbb|.
static bool AddNameWithCommonName(CBB* cbb, absl::string_view common_name) {
  // See RFC 4519.
  static const uint8_t kCommonName[] = {0x55, 0x04, 0x03};

  // See RFC 5280, section 4.1.2.4.
  CBB rdns, rdn, attr, type, value;
  if (!CBB_add_asn1(cbb, &rdns, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&rdns, &rdn, CBS_ASN1_SET) ||
      !CBB_add_asn1(&rdn, &attr, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&attr, &type, CBS_ASN1_OBJECT) ||
      !CBB_add_bytes(&type, kCommonName, sizeof(kCommonName)) ||
      !CBB_add_asn1(&attr, &value, CBS_ASN1_UTF8STRING) ||
      !CBB_add_bytes(&value,
                     reinterpret_cast<const uint8_t*>(common_name.data()),
                     common_name.size()) ||
      !CBB_flush(cbb)) {
    return false;
  }
  return true;
}

static bool AddTime(CBB* cbb, absl::Time time) {
  der::GeneralizedTime generalized_time;
  if (!der::EncodeTimeAsGeneralizedTime(time, &generalized_time)) return false;

  // Per RFC 5280, 4.1.2.5, times which fit in UTCTime must be encoded as
  // UTCTime rather than GeneralizedTime.
  CBB child;
  uint8_t* out;
  if (generalized_time.InUTCTimeRange()) {
    return CBB_add_asn1(cbb, &child, CBS_ASN1_UTCTIME) &&
           CBB_add_space(&child, &out, der::kUTCTimeLength) &&
           der::EncodeUTCTime(generalized_time, out) && CBB_flush(cbb);
  }

  return CBB_add_asn1(cbb, &child, CBS_ASN1_GENERALIZEDTIME) &&
         CBB_add_space(&child, &out, der::kGeneralizedTimeLength) &&
         der::EncodeGeneralizedTime(generalized_time, out) && CBB_flush(cbb);
}

static bool AddRSASignatureAlgorithm(CBB* cbb) {
  // See RFC 4055.
  static const uint8_t kSHA256WithRSAEncryption[] = {
      0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b};

  // An AlgorithmIdentifier is described in RFC 5280, 4.1.1.2.
  CBB sequence, oid, params;
  if (!CBB_add_asn1(cbb, &sequence, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&sequence, &oid, CBS_ASN1_OBJECT) ||
      !CBB_add_bytes(&oid, kSHA256WithRSAEncryption,
                     sizeof(kSHA256WithRSAEncryption)) ||
      !CBB_add_asn1(&sequence, &params, CBS_ASN1_NULL) ||
      !CBB_flush(cbb)) {
    return false;
  }
  return true;
}

static bssl::UniquePtr<EVP_PKEY> CreateRSAPrivateKey() {
  bssl::UniquePtr<RSA> rsa_key(RSA_new());
  bssl::UniquePtr<BIGNUM> e(BN_new());
  if (!rsa_key.get() || !e.get() || !BN_set_word(e.get(), 65537L))
    return nullptr;

  if (!RSA_generate_key_ex(rsa_key.get(), 1024, e.get(), nullptr)) {
    return nullptr;
  }

  bssl::UniquePtr<EVP_PKEY> result(EVP_PKEY_new());
  if (!result || !EVP_PKEY_set1_RSA(result.get(), rsa_key.get())) {
    return nullptr;
  }

  return result;
}

namespace x509_util {

bool CreateSelfSignedCert(const std::string& subject, uint32_t serial_number,
                          absl::Time not_valid_before,
                          absl::Time not_valid_after,
                          std::string* der_encoded) {
  // Because |subject| only contains a common name and starts with 'CN=', there
  // is no need for a full RFC 2253 parser here. Do some sanity checks though.
  static const char kCommonNamePrefix[] = "CN=";
  if (!absl::StartsWith(subject, kCommonNamePrefix) ||
      absl::StrContains(subject, ",")) {
    LOG(ERROR) << "Subject must begin with " << kCommonNamePrefix
               << " and contain no commas";
    return false;
  }
  absl::string_view common_name = subject;
  common_name.remove_prefix(sizeof(kCommonNamePrefix) - 1);
  bssl::UniquePtr<EVP_PKEY> key = CreateRSAPrivateKey();

  // See RFC 5280, section 4.1. First, construct the TBSCertificate.
  bssl::ScopedCBB cbb;
  CBB tbs_cert, version, validity;
  uint8_t* tbs_cert_bytes;
  size_t tbs_cert_len;
  if (!CBB_init(cbb.get(), 1024) ||
      !CBB_add_asn1(cbb.get(), &tbs_cert, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&tbs_cert, &version,
                    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
      !CBB_add_asn1_uint64(&version, 2 /* X509v3 */) ||
      !CBB_add_asn1_uint64(&tbs_cert, serial_number) ||
      !AddRSASignatureAlgorithm(&tbs_cert) ||            // signature
      !AddNameWithCommonName(&tbs_cert, common_name) ||  // issuer
      !CBB_add_asn1(&tbs_cert, &validity, CBS_ASN1_SEQUENCE) ||
      !AddTime(&validity, not_valid_before) ||
      !AddTime(&validity, not_valid_after) ||
      !AddNameWithCommonName(&tbs_cert, common_name) ||  // subject
      !EVP_marshal_public_key(&tbs_cert, key.get())) {   // subjectPublicKeyInfo
    return false;
  }

  if (!CBB_finish(cbb.get(), &tbs_cert_bytes, &tbs_cert_len)) return false;
  bssl::UniquePtr<uint8_t> delete_tbs_cert_bytes(tbs_cert_bytes);

  // Sign the TBSCertificate and write the entire certificate.
  CBB cert, signature;
  bssl::ScopedEVP_MD_CTX ctx;
  uint8_t* sig_out;
  size_t sig_len;
  uint8_t* cert_bytes;
  size_t cert_len;
  if (!CBB_init(cbb.get(), tbs_cert_len) ||
      !CBB_add_asn1(cbb.get(), &cert, CBS_ASN1_SEQUENCE) ||
      !CBB_add_bytes(&cert, tbs_cert_bytes, tbs_cert_len) ||
      !AddRSASignatureAlgorithm(&cert) ||
      !CBB_add_asn1(&cert, &signature, CBS_ASN1_BITSTRING) ||
      !CBB_add_u8(&signature, 0 /* no unused bits */) ||
      !EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr,
                          key.get()) ||
      // Compute the maximum signature length.
      !EVP_DigestSign(ctx.get(), nullptr, &sig_len, tbs_cert_bytes,
                      tbs_cert_len) ||
      !CBB_reserve(&signature, &sig_out, sig_len) ||
      // Actually sign the TBSCertificate.
      !EVP_DigestSign(ctx.get(), sig_out, &sig_len, tbs_cert_bytes,
                      tbs_cert_len) ||
      !CBB_did_write(&signature, sig_len) ||
      !CBB_finish(cbb.get(), &cert_bytes, &cert_len)) {
    return false;
  }
  bssl::UniquePtr<uint8_t> delete_cert_bytes(cert_bytes);
  der_encoded->assign(reinterpret_cast<char*>(cert_bytes), cert_len);
  return true;
}

}  // namespace x509_util

}  // namespace bssl
