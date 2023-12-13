#ifndef BSSL_VERIFY_H_
#define BSSL_VERIFY_H_

#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/pki/signature_verify_cache.h>

namespace bssl {
class CertIssuerSourceStatic;
class TrustStoreInMemory;
}  // namespace bssl

namespace verify {

class OPENSSL_EXPORT TrustStore {
 public:
  std::unique_ptr<bssl::TrustStoreInMemory> trust_store;

  ~TrustStore();

  // FromDER returns a |TrustStore| derived from interpreting the |der_certs| as
  // a bunch of DER-encoded certs, concatenated. In the event of a failure no
  // value is returned and a diagnostic string is placed in |out_diagnostic|
  static std::optional<std::unique_ptr<TrustStore>> FromDER(
      std::string_view der_certs, std::string *out_diagnostic);

  // FromDER returns a |TrustStore| consisting of the supplied DER-encoded
  // certs in |der_certs|. In the event of a failure no value is returned and a
  // diagnostic string is placed in |out_diagnostic|
  static std::optional<std::unique_ptr<TrustStore>> FromDER(
      const std::vector<std::string_view> &der_certs,
      std::string *out_diagnostic);
};

class OPENSSL_EXPORT CertPool {
 public:
  CertPool();
  virtual ~CertPool();

  std::unique_ptr<bssl::CertIssuerSourceStatic> impl_;

  CertPool(const CertPool &) = delete;
  CertPool &operator=(const CertPool &) = delete;
};

// Opts contains all the options for a certificate verification.
class OPENSSL_EXPORT Opts {
 public:
  // The key purpose (extended key usage) to check for during verification.
  enum class KeyPurpose {
    ANY_EKU,
    SERVER_AUTH,
    CLIENT_AUTH,
    SERVER_AUTH_STRICT,
    CLIENT_AUTH_STRICT,
  };

  Opts();

  KeyPurpose key_purpose = KeyPurpose::SERVER_AUTH;
  std::string_view leaf_cert;
  std::vector<std::string_view> intermediates;

  // extra_intermediates optionally points to a pool of common intermediates.
  const CertPool *extra_intermediates = nullptr;
  // trust_store points to the set of root certificates to trust.
  const TrustStore *trust_store = nullptr;
  // min_rsa_modulus_length is the minimum acceptable RSA key size in a chain.
  size_t min_rsa_modulus_length = 1024;
  // time is the time in POSIX seconds since the POSIX epoch at which to
  // validate the chain. It defaults to the current time if not set.
  std::optional<int64_t> time;
  // insecurely_allow_sha1 allows verification of signatures that use SHA-1
  // message digests.  This option is insecure and should not be used.
  bool insecurely_allow_sha1 = false;

  // max_iteration_count, if not zero, limits the number of times path building
  // will try to append an intermediate to a potential path. This bounds the
  // amount of time that a verification attempt can take, at the risk of
  // rejecting cases that would be solved if only more effort were used.
  uint32_t max_iteration_count = 0;

  // Sets an optional deadline for completing path building. It defaults
  // to std::chrono::time_point::max() if it not set. If |deadline| has a
  // value that has passed based on comparison to
  // std::chrono::steady_clock::now(), and path building has not completed,
  // path building will stop. Note that this is not a hard limit, there is no
  // guarantee how far past |deadline| time will be when path building is
  // aborted.
  std::optional<std::chrono::time_point<std::chrono::steady_clock>> deadline;

  // max_path_building_depth, if not zero, limits the depth of the path that the
  // path building algorithm attempts to build between leafs and roots. Using
  // this comes at the risk of rejecting cases that would be solved if only one
  // more certificate is added to the path.
  uint32_t max_path_building_depth = 0;

  // signature_verify_cache, if not nullptr, points to an object implementing a
  // signature verification cache derived from
  // <openssl/pki/signature_verify_cache.h>
  bssl::SignatureVerifyCache *signature_verify_cache = nullptr;

  Opts(const Opts &) = delete;
  Opts &operator=(const Opts &) = delete;
};

class VerifyStatus;

// Error describes a failed certificate chain validation.  Because a presented
// certificate chain may have many problems, and because the underlying code
// changes over time, we make few guarantees.
//
// See the AsStatus() method, and feel free to consult ssl-tls@ if you need to
// add a private-use method that has a well-defined and unchanging meaning.
class OPENSSL_EXPORT Error {
 public:
  Error();
  Error &operator=(const Error &other);

  // AsString returns a friendly human-readable representation of an error. The
  // string aims to be useful to debugging, but it is not guaranteed to be
  // unchanging.  That is to say, a given chain may produce error A one day, and
  // error B the next day, as the underlying code changes.
  //
  // Needless to say, one should not attempt to parse the string that is
  // returned.
  std::string AsString() const;

  // DiagnosticString returns a string of diagnostic information related to this
  // error. The string aims to be useful to debugging, but it is not guaranteed
  // to be unchanging.  That is to say, a given chain may produce error A one
  // day, and error B the next day, as the underlying code changes. The string
  // may be empty if no diagnostic information was available.
  //
  // Needless to say, one should not attempt to parse the string that is
  // returned.
  std::string DiagnosticString() const;

 private:
  friend std::optional<std::vector<std::vector<std::string>>> VerifyInternal(
      const Opts &opts, Error *out_error, VerifyStatus *out_status,
      bool all_paths);

  // offset gives the certificate within the path to which this error pertains.
  // 0 means the leaf certificate.  The ordering of the certificates is not
  // knowable to the caller in all cases.  In particular, the path may include
  // certificates not presented by the peer, and it may order certificates
  // differently from the order in which the peer presented them.
  //
  // The offset is only meaningful for errors that start with |CERTIFICATE|.
  size_t offset_ = 0;

  // Code is the private representation of the "single best error" that we could
  // find.  Error representations exposed to callers derive from this one.
  enum class Code {
    // NO_PATH means that no path could be found from the leaf cert to any
    // trust anchor.  |CERTIFICATE_SELF_SIGNED| is a special case of this error.
    NO_PATH,

    // CERTIFICATE_REJECTED means that the certificate was formally invalid, and
    // was not considered.  This error is returned only for the leaf
    // certificate: invalid intermediate certificates are silently discarded,
    // rather than causing validation to fail.
    CERTIFICATE_REJECTED,

    // CERTIFICATE_REVOKED means that the certificate has been blacklisted
    // by Google, due to (for example) misissuance or key compromise, or that it
    // has been revoked by its issuer.
    CERTIFICATE_REVOKED,

    // CERTIFICATE_SELF_SIGNED is a special case of |NO_PATH|.  It means that
    // the certificate was self-signed.
    CERTIFICATE_SELF_SIGNED,

    // CERTIFICATE_EXPIRED means that the validation time is after the
    // certificate's |notAfter| timestamp.
    CERTIFICATE_EXPIRED,

    // CERTIFICATE_NOT_YET_VALID means that the validation time is before the
    // certificate's |notBefore| timestamp.
    CERTIFICATE_NOT_YET_VALID,

    // CERTIFICATE_LACKS_SERVER_AUTH means that the certificate's EKU
    // extension lacks |SERVER_AUTH|.
    CERTIFICATE_LACKS_SERVER_AUTH,

    // CERTIFICATE_LACKS_CLIENT_AUTH means that the certificate's EKU
    // extension lacks |CLIENT_AUTH|.
    CERTIFICATE_LACKS_CLIENT_AUTH,

    // CERTIFICATE_UNACCEPTABLE_SIGALG means that a certificate used a
    // disallowed (for example, SHA-1) signature algorithm.
    CERTIFICATE_UNACCEPTABLE_SIGALG,

    // CERTIFICATE_SIGNATURE_VERIFY_FAILED means that the certificate's
    // signature failed to verify.
    CERTIFICATE_SIGNATURE_VERIFY_FAILED,

    // CERTIFICATE_OTHER_ERROR means that something was wrong with the
    // certificate that cannot be characterized by another error.
    CERTIFICATE_OTHER_ERROR,

    // ITERATION_COUNT_EXCEEDED means that the limit configured in
    // |Opts.max_iteration_count|
    // was hit and so the search for a valid path terminated early.
    ITERATION_COUNT_EXCEEDED,

    // DEADLINE_EXCEEDED means that the limit configured in |Opts.deadline|
    // was hit and so the search for a valid path terminated early.
    DEADLINE_EXCEEDED,

    // DEPTH_LIMIT_REACHED means that path building was not able to find a path
    // within the given depth limit.
    DEPTH_LIMIT_REACHED,

    // UNKNOWN_ERROR means that something was wrong with the chain that cannot
    // be characterized by another error.
    UNKNOWN_ERROR,

  };
  Code code_ = Code::UNKNOWN_ERROR;
  std::string diagnostic_;

  Error(Code code, size_t offset, std::string_view diagnostic);
};

// VerifyStatus describes the status of a certificate verification attempt.
class OPENSSL_EXPORT VerifyStatus {
 public:
  VerifyStatus();

  // IterationCount returns the total number of attempted certificate additions
  // to any potential path while performing path building for verification. It
  // is the same value which may be bound by max_iteration_count in Opts.
  size_t IterationCount() const;

  // MaxDepthSeen returns the maximum path depth seen during path building.
  size_t MaxDepthSeen() const;

 private:
  friend std::optional<std::vector<std::vector<std::string>>> VerifyInternal(
      const Opts &opts, Error *out_error, VerifyStatus *out_status,
      bool all_paths);
  size_t iteration_count_ = 0;
  size_t max_depth_seen_ = 0;
};

// Verify verifies |opts.leaf_cert| using the other values in |opts|. It
// returns either an error, or else a validated chain from leaf to root.
//
// In the event of an error return, |out_error| will be updated with information
// about the error.  It may be |nullptr|.
//
// Status information about the verification will be returned in |out_status|.
// It may be |nullptr|.
std::optional<std::vector<std::string>> Verify(
    const Opts &opts, Error *out_error = nullptr,
    VerifyStatus *out_status = nullptr);

// VerifyAllPaths verifies |opts.leaf_cert| using the other values in |opts|,
// and returns all possible valid chains from the leaf to a root. If no chains
// exist, it returns an error.
std::optional<std::vector<std::vector<std::string>>> VerifyAllPaths(
    const Opts &opts);

// NewCertPoolFromCerts returns a |CertPool| consisting of the supplied
// DER-encoded certs in |der_certs|. In the event of a failure no value is
// returned and a diagnostic string is placed in |out_diagnostic|
std::optional<std::unique_ptr<CertPool>> NewCertPoolFromCerts(
    const std::vector<std::string_view> &der_certs,
    std::string *out_diagnostic);

}  // namespace verify

#endif  // BSSL_VERIFY_H_
