#ifndef BSSL_FILLINS_OPENSSL_UTIL_H
#define BSSL_FILLINS_OPENSSL_UTIL_H

#include <openssl/base.h>

#include <string>

namespace bssl {

namespace fillins {

// Place an instance of this class on the call stack to automatically clear
// the OpenSSL error stack on function exit.
class OPENSSL_EXPORT OpenSSLErrStackTracer {
 public:
  OPENSSL_EXPORT OpenSSLErrStackTracer();
  OPENSSL_EXPORT ~OpenSSLErrStackTracer();
};

}  // namespace fillins

}  // namespace bssl

#endif  // BSSL_FILLINS_OPENSSL_UTIL_H
