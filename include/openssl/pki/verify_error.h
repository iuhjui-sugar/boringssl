#ifndef BSSL_VERIFY_ERROR_H_
#define BSSL_VERIFY_ERROR_H_

#include <string>
#include <string_view>

namespace bssl {

// VerifyError describes certificate chain validation result.
class OPENSSL_EXPORT VerifyError {
 public:
  VerifyError();
  VerifyError &operator=(const VerifyError &other);

  // DiagnosticString returns a string of diagnostic information related to this
  // verification attempt. The string aims to be useful to debugging, but it
  // is not guaranteed to be unchanging.  That is to say, a given chain may
  // produce error A one day, and error B the next day, as the underlying code
  // changes. The string may be empty if no diagnostic information was
  // available.
  //
  // The DiagnosticString is specifically not guaranteed to be unchanging for
  // any given error code, as the diagnostic error message can contain information
  // specific to the verification attempt and chain presented, due to there
  // being multiple possible ways for, as an example, a certificate to be invalid,
  // or that we are unable to build a path to a trust anchor.
  //
  // Needless to say, one should not attempt to parse the string that is
  // returned.
  std::string DiagnosticString() const;

  // Index returns the certificate in the chain for which the error
  // occured, starting with 0 for the leaf certificate. If the error is
  // not specific to a certificate, -1 is returned.
  ptrdiff_t Index() const;

  // Code is the representation of a single error that we could
  // find.
  enum class StatusCode {
    // PATH_VERIFIED means there were no errors, the chain is valid.
    PATH_VERIFIED,

    // CERTIFICATE_INVALID means that the certificate was rejected
    // as invalid.
    CERTIFICATE_INVALID,

    // CERTIFICATE_INVALID_SIGNATURE means that the certificate's
    // signature failed to verify.
    CERTIFICATE_INVALID_SIGNATURE,

    // CERTIFICATE_UNSUPPOERTED_KEYE means that the certificate's
    // key type and/or size is not supported.
    CERTIFICATE_UNSUPPORTED_KEY,

    // CERTIFICATE_REVOKED means that the certificate has been revoked.
    CERTIFICATE_REVOKED,

    // CERTIFICATE_NO_REVOCATION_MECHANISM means that revocation checking was
    // required and no revocation mechanism was given for the certificate
    CERTIFICATE_NO_REVOCATION_MECHANISM,

    // CERTIFICATE_NO_REVOCATION_MECHANISM means that revocation checking was
    // required and we were unable to check if the certificate was revoked via
    // any revocation mechanism.
    CERTIFICATE_UNABLE_TO_CHECK_REVOCATION,

    // CERTIFICATE_EXPIRED means that the validation time is after the
    // certificate's |notAfter| timestamp.
    CERTIFICATE_EXPIRED,

    // CERTIFICATE_NOT_YET_VALID means that the validation time is before the
    // certificate's |notBefore| timestamp.
    CERTIFICATE_NOT_YET_VALID,

    // CERTIFICATE_NO_MATCHING_EKU means that the certificate's EKU
    // does not allow the certificate to be used for the intended
    // purpose.
    CERTIFICATE_NO_MATCHING_EKU,

    // PATH_NOT_FOUND means that no path could be found from the leaf cert to
    // any trust anchor.
    PATH_NOT_FOUND,

    // PATH_ITERATION_COUNT_EXCEEDED means that the limit configured in
    // |Opts.max_iteration_count|
    // was hit and so the search for a valid path terminated early.
    PATH_ITERATION_COUNT_EXCEEDED,

    // PATH_DEADLINE_EXCEEDED means that the limit configured in |Opts.deadline|
    // was hit and so the search for a valid path terminated early.
    PATH_DEADLINE_EXCEEDED,

    // PATH_DEPTH_LIMIT_REACHED means that path building was not able to find a
    // path within the given depth limit.
    PATH_DEPTH_LIMIT_REACHED,

    // PATH_MULTIPLE_ERRORS indicates that there are multiple
    // errors present on the chain.
    PATH_MULTIPLE_ERRORS,

    // VERIFICATION_FAILURE means that something is wrong with the returned path
    // that is not associated to a single certificate
    VERIFICATION_FAILURE,
  };

  VerifyError(StatusCode code, ptrdiff_t offset, std::string_view diagnostic);

  // Code returns the indicated error code for the certificate path.
  StatusCode Code() const;

 private:
  ptrdiff_t offset_ = -1;
  StatusCode code_ = StatusCode::VERIFICATION_FAILURE;
  std::string diagnostic_;
};

} // namespace bssl

#endif  // BSSL_VERIFY_ERROR_H_
