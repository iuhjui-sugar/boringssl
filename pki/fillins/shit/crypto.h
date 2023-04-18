#ifndef THIRD_PARTY_CHROMIUM_CERTIFICATE_VERIFIER_FILLINS_CRYPTO_H_
#define THIRD_PARTY_CHROMIUM_CERTIFICATE_VERIFIER_FILLINS_CRYPTO_H_

#include <stddef.h>  // for size_t
#include <string>    // for string

#include "third_party/absl/strings/string_view.h"  // for string_view
#include "third_party/openssl/sha.h"

namespace bssl {

namespace fillins {

// These functions perform SHA-256 operations.
//
// Functions for SHA-384 and SHA-512 can be added when the need arises.

static const size_t kSHA256Length = 32;  // Length in bytes of a SHA-256 hash.

// Computes the SHA-256 hash of the input string 'str' and stores the first
// 'len' bytes of the hash in the output buffer 'output'.  If 'len' > 32,
// only 32 bytes (the full hash) are stored in the 'output' buffer.
void SHA256HashString(absl::string_view str, void* output, size_t len);

// Convenience version of the above that returns the result in a 32-byte
// string.
std::string SHA256HashString(absl::string_view str);

// These functions perform SHA-1 operations.

static const size_t kSHA1Length = 20;  // Length in bytes of a SHA-1 hash.

// Computes the SHA-1 hash of the input string |str| and returns the full
// hash.
std::string SHA1HashString(absl::string_view str);

}  // namespace fillins
}  // namespace bssl

#endif  // THIRD_PARTY_CHROMIUM_CERTIFICATE_VERIFIER_FILLINS_CRYPTO_H_
