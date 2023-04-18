#include "openssl_util.h"

#include <openssl/err.h>

namespace bssl {

namespace fillins {

OPENSSL_EXPORT OpenSSLErrStackTracer::OpenSSLErrStackTracer() {}

OPENSSL_EXPORT OpenSSLErrStackTracer::~OpenSSLErrStackTracer() {
  ERR_clear_error();
}

}  // namespace fillins

}  // namespace bssl
