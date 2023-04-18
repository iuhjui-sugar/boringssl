#ifndef EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_STRING_UTIL_H
#define EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_STRING_UTIL_H

#include <string>
#include <string_view>
#include <vector>

namespace bssl {

namespace fillins {

std::string HexEncode(const void *bytes, size_t size);

std::string CollapseWhitespaceASCII(std::string_view text,
                                    bool trim_sequences_with_line_breaks);

bool EqualsCaseInsensitiveASCII(std::string_view a, std::string_view b);

bool IsAsciiAlpha(char c);

bool IsAsciiDigit(char c);

void ReplaceSubstringsAfterOffset(std::string *s, size_t offset,
                                  std::string_view find,
                                  std::string_view replace);

std::string HexDecode(std::string_view hex);

}  // namespace fillins

}  // namespace bssl

#endif  // EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_STRING_UTIL_H
