#include "openssl_util.h"

#include <openssl/err.h>

namespace bssl {

namespace fillins {

OpenSSLErrStackTracer::OpenSSLErrStackTracer() {}

OpenSSLErrStackTracer::~OpenSSLErrStackTracer() {
  ERR_clear_error();
}

}  // namespace fillins

}  // namespace bssl
