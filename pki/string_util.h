// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_PKI_STRING_UTIL_H_
#define NET_CERT_PKI_STRING_UTIL_H_


#include <stdint.h>
#include <cassert>
#include <string_view>
#include <vector>

namespace bssl::string_util {

// Returns true if the characters in |str| are all ASCII, false otherwise.
bool IsAscii(std::string_view str);

// Compares |str1| and |str2| ASCII case insensitively (independent of locale).
// Returns true if |str1| and |str2| match.
bool IsEqualNoCase(std::string_view str1,
                                      std::string_view str2);

// Compares |str1| and |prefix| ASCII case insensitively (independent of
// locale). Returns true if |str1| starts with |prefix|.
bool StartsWithNoCase(std::string_view str,
                                         std::string_view prefix);

// Compares |str1| and |suffix| ASCII case insensitively (independent of
// locale). Returns true if |str1| starts with |suffix|.
bool EndsWithNoCase(std::string_view str,
                                       std::string_view suffix);

// Finds and replaces all occurrences of |find| of non zero length with
// |replace| in |str|, returning the result.
std::string FindAndReplace(std::string_view str,
                                              std::string_view find,
                                              std::string_view replace);

// TODO(bbe) transition below to c++20
// Compares |str1| and |prefix|. Returns true if |str1| starts with |prefix|.
bool StartsWith(std::string_view str,
                                   std::string_view prefix);

// TODO(bbe) transition below to c++20
// Compares |str1| and |suffix|. Returns true if |str1| ends with |suffix|.
bool EndsWith(std::string_view str, std::string_view suffix);

// Returns a hexadecimal string encoding |data| of length |length|.
std::string HexEncode(const uint8_t* data, size_t length);

// Returns a decimal string representation of |i|.
std::string NumberToDecimalString(int i);

// Splits |str| on |split_char| returning the list of resulting strings.
std::vector<std::string_view> SplitString(
    std::string_view str,
    char split_char);

}  // namespace net::string_util

#endif  // NET_CERT_PKI_STRING_UTIL_H_
