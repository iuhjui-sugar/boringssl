#include <openssl/base.h>
#include <openssl/pki/verify_error.h>

namespace bssl {

VerifyError::VerifyError() {}

VerifyError::VerifyError(StatusCode code, ssize_t offset,
                         std::string_view diagnostic)
    : offset_(offset), code_(code), diagnostic_(diagnostic) {}

VerifyError &VerifyError::operator=(const VerifyError &other) {
  code_ = other.code_;
  offset_ = other.offset_;
  diagnostic_ = other.diagnostic_;
  return *this;
}

std::string VerifyError::DiagnosticString() const { return diagnostic_; }

ssize_t VerifyError::Index() const { return offset_; }

VerifyError::StatusCode VerifyError::Code() const { return code_; }

}  // namespacee bssl
