#ifndef EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_FILE_UTIL_H
#define EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_FILE_UTIL_H

#include "path_service.h"

#include <string>

namespace bssl {

namespace fillins {

bool ReadFileToString(const FilePath& path, std::string *out);

}  // namespace fillins

}  // namespace bssl

#endif  // EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_FILE_UTIL_H
