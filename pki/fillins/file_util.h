#ifndef BSSL_FILLINS_FILE_UTIL_H
#define BSSL_FILLINS_FILE_UTIL_H
#include <openssl/base.h>

#include "path_service.h"

#include <string>

namespace bssl {

namespace fillins {

OPENSSL_EXPORT bool ReadFileToString(const FilePath &path, std::string *out);

}  // namespace fillins

}  // namespace bssl

#endif  // BSSL_FILLINS_FILE_UTIL_H
