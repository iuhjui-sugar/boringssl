#ifndef EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_STRING_SPLIT_H
#define EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_STRING_SPLIT_H

#include <vector>

#include "third_party/absl/strings/string_view.h"

namespace bssl {

namespace fillins {

enum TrimPositions {
  TRIM_NONE     = 0,
  TRIM_LEADING  = 1 << 0,
  TRIM_TRAILING = 1 << 1,
  TRIM_ALL      = TRIM_LEADING | TRIM_TRAILING,
};

enum WhitespaceHandling {
  KEEP_WHITESPACE,
  TRIM_WHITESPACE,
};

enum SplitResult {
  // Strictly return all results.
  //
  // If the input is ",," and the separator is ',' this will return a
  // vector of three empty strings.
  SPLIT_WANT_ALL,

  // Only nonempty results will be added to the results. Multiple separators
  // will be coalesced. Separators at the beginning and end of the input will
  // be ignored. With TRIM_WHITESPACE, whitespace-only results will be dropped.
  //
  // If the input is ",," and the separator is ',', this will return an empty
  // vector.
  SPLIT_WANT_NONEMPTY,
};

std::vector<absl::string_view> SplitStringPieceUsingSubstr(
    absl::string_view input, absl::string_view delimiter,
    WhitespaceHandling whitespace, SplitResult result_type);

std::vector<std::string> SplitString(absl::string_view input,
                                     absl::string_view separators,
                                     WhitespaceHandling whitespace,
                                     SplitResult result_type);

}  // namespace fillins

}  // namespace bssl

#endif  // EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_STRING_SPLIT_H
