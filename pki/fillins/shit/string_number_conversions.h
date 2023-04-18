#ifndef THIRD_PARTY_CHROMIUM_CERTIFICATE_VERIFIER_FILLINS_STRING_NUMBER_CONVERSIONS_H_
#define THIRD_PARTY_CHROMIUM_CERTIFICATE_VERIFIER_FILLINS_STRING_NUMBER_CONVERSIONS_H_

#include <vector>

#include "third_party/absl/strings/string_view.h"

namespace bssl {
namespace fillins {

// Best-effort conversion of a hex string (like "0A") to bytes.  input.size()
// must be evenly divisible by 2.  Leading 0x or +/- are not allowed.
bool HexStringToBytes(absl::string_view input, std::vector<uint8_t>* output);

// Same as HexStringToBytes, but for a std::string.
bool HexStringToString(absl::string_view input, std::string* output);

}  // namespace fillins
}  // namespace bssl

#endif  // THIRD_PARTY_CHROMIUM_CERTIFICATE_VERIFIER_FILLINS_STRING_NUMBER_CONVERSIONS_H_
