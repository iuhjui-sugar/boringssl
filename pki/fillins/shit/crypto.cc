#include "third_party/chromium_certificate_verifier/fillins/crypto.h"

#include <stdint.h>  // for uint8_t
#include <string.h>  // for memcpy

#include "third_party/absl/strings/string_view.h"  // for string_view
#include "third_party/openssl/sha.h"  // for SHA256_DIGEST_LENGTH, SHA1, etc

namespace bssl {

namespace fillins {

void SHA256HashString(absl::string_view str, void* output, size_t len) {
  uint8_t digest[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const uint8_t*>(str.data()), str.length(), digest);
  memcpy(output, digest,
         len < SHA256_DIGEST_LENGTH ? len : SHA256_DIGEST_LENGTH);
}

std::string SHA256HashString(absl::string_view str) {
  uint8_t digest[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const uint8_t*>(str.data()), str.length(), digest);
  return {reinterpret_cast<const char*>(digest), sizeof(digest)};
}

std::string SHA1HashString(absl::string_view str) {
  uint8_t digest[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const uint8_t*>(str.data()), str.length(), digest);
  return {reinterpret_cast<const char*>(digest), sizeof(digest)};
}

}  // namespace fillins
}  // namespace bssl
