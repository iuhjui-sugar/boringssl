#ifndef EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_OPENSSL_UTIL_H
#define EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_OPENSSL_UTIL_H

#include <openssl/base.h>

#include <string>

namespace bssl {

namespace fillins {

// Place an instance of this class on the call stack to automatically clear
// the OpenSSL error stack on function exit.
class OPENSSL_EXPORT OpenSSLErrStackTracer {
 public:
  OpenSSLErrStackTracer();
  ~OpenSSLErrStackTracer();

};

}  // namespace fillins

}  // namespace bssl

#endif  // EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_OPENSSL_UTIL_H
