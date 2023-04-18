#include "third_party/chromium_certificate_verifier/fillins/string_number_conversions.h"

#include "base/logging.h"
#include "third_party/absl/strings/escaping.h"  // for HexStringToBytes, etc

namespace bssl {
namespace fillins {

bool HexStringToBytes(absl::string_view input, std::vector<uint8_t> *output) {
  DCHECK_EQ(output->size(), 0u);
  std::string result = absl::HexStringToBytes(input);
  if (result.length() != input.length() / 2) {
    return false;
  }
  output->reserve(result.length());
  for (char c : result) {
    output->push_back(c);
  }
  return true;
}

bool HexStringToString(absl::string_view input, std::string *output) {
  std::string result = absl::HexStringToBytes(input);
  if (result.length() != input.length() / 2) {
    return false;
  }
  *output = std::move(result);
  return true;
}

}  // namespace fillins
}  // namespace bssl
