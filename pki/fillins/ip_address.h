#ifndef EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_IP_ADDRESS
#define EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_IP_ADDRESS

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "../check.h"

namespace bssl {

namespace fillins {

typedef std::string IPAddressBytes;

class IPAddress {
 public:
  enum : size_t { kIPv4AddressSize = 4, kIPv6AddressSize = 16 };

  IPAddress();
  IPAddress(const uint8_t* address, size_t address_len);
  IPAddress(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3);
  IPAddress(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3,
            uint8_t b4, uint8_t b5, uint8_t b6, uint8_t b7,
            uint8_t b8, uint8_t b9, uint8_t b10, uint8_t b11,
            uint8_t b12, uint8_t b13, uint8_t b14, uint8_t b15);

  static IPAddress IPv4AllZeros();

  bool IsIPv4() const;
  bool IsIPv6() const;
  bool IsValid() const;

  const uint8_t* data() const;
  size_t size() const;
  const IPAddressBytes& bytes() const;

  bool operator==(const IPAddress& other) const { return addr_ == other.addr_; }

 private:
  static IPAddress AllZeros(size_t num_zero_bytes);
  std::string addr_;
};

bool IPAddressMatchesPrefix(const IPAddress& ip_address,
                            const IPAddress& ip_prefix,
                            size_t prefix_length_in_bits);

unsigned MaskPrefixLength(const IPAddress& mask);

}  // namespace fillins

}  // namespace bssl

#endif  // EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_IP_ADDRESS
