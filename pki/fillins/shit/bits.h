#ifndef THIRD_PARTY_CHROMIUM_CERTIFICATE_VERIFIER_FILLINS_BITS_H
#define THIRD_PARTY_CHROMIUM_CERTIFICATE_VERIFIER_FILLINS_BITS_H

#include <type_traits>

#include "third_party/absl/types/span.h"

namespace bssl {

namespace fillins {

template <typename T, typename = std::enable_if_t<std::is_integral<T>::value>>
constexpr bool IsPowerOfTwo(T value) {
  return value > 0 && (value & (value - 1)) == 0;
}

template <typename T>
constexpr absl::Span<const uint8_t> as_bytes(absl::Span<T> s) noexcept {
  return {reinterpret_cast<const uint8_t*>(s.data()), s.size() * sizeof(T)};
}

}  // namespace fillins

}  // namespace bssl

#endif  // THIRD_PARTY_CHROMIUM_CERTIFICATE_VERIFIER_FILLINS_BITS_H
