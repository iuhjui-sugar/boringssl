#ifndef EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_BASE64_H
#define EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_BASE64_H

#include <string>
#include <string_view>

namespace bssl {

namespace fillins {

bool Base64Encode(const std::string_view& input, std::string* output);

bool Base64Decode(const std::string_view& input, std::string* output);

}  // namespace fillins

}  // namespace bssl

#endif  // EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_BASE64_H
