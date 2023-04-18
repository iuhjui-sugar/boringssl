// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_PKI_GENERAL_NAMES_H_
#define NET_CERT_PKI_GENERAL_NAMES_H_

#include <memory>
#include <vector>

#include "fillins/ip_address.h"

#include "cert_error_id.h"

namespace bssl {

class CertErrors;

extern const CertErrorId kFailedParsingGeneralName;

namespace der {
class Input;
}  // namespace der

// Bitfield values for the GeneralName types defined in RFC 5280. The ordering
// and exact values are not important, but match the order from the RFC for
// convenience.
enum GeneralNameTypes {
  GENERAL_NAME_NONE = 0,
  GENERAL_NAME_OTHER_NAME = 1 << 0,
  GENERAL_NAME_RFC822_NAME = 1 << 1,
  GENERAL_NAME_DNS_NAME = 1 << 2,
  GENERAL_NAME_X400_ADDRESS = 1 << 3,
  GENERAL_NAME_DIRECTORY_NAME = 1 << 4,
  GENERAL_NAME_EDI_PARTY_NAME = 1 << 5,
  GENERAL_NAME_UNIFORM_RESOURCE_IDENTIFIER = 1 << 6,
  GENERAL_NAME_IP_ADDRESS = 1 << 7,
  GENERAL_NAME_REGISTERED_ID = 1 << 8,
  GENERAL_NAME_ALL_TYPES = (1 << 9) - 1,
};

// Represents a GeneralNames structure. When processing GeneralNames, it is
// often necessary to know which types of names were present, and to check
// all the names of a certain type. Therefore, a bitfield of all the name
// types is kept, and the names are split into members for each type.
struct GeneralNames {
  // Controls parsing of iPAddress names in ParseGeneralName.
  // IP_ADDRESS_ONLY parses the iPAddress names as a 4 or 16 byte IP address.
  // IP_ADDRESS_AND_NETMASK parses the iPAddress names as 8 or 32 bytes
  // containing an IP address followed by a netmask.
  enum ParseGeneralNameIPAddressType {
    IP_ADDRESS_ONLY,
    IP_ADDRESS_AND_NETMASK,
  };

  GeneralNames();
  ~GeneralNames();

  // Create a GeneralNames object representing the DER-encoded
  // |general_names_tlv|. The returned object may reference data from
  // |general_names_tlv|, so is only valid as long as |general_names_tlv| is.
  // Returns nullptr on failure, and may fill |errors| with
  // additional information. |errors| must be non-null.
  static std::unique_ptr<GeneralNames> Create(
      const der::Input& general_names_tlv,
      CertErrors* errors);

  // As above, but takes the GeneralNames sequence value, without the tag and
  // length.
  static std::unique_ptr<GeneralNames> CreateFromValue(
      const der::Input& general_names_value,
      CertErrors* errors);

  // DER-encoded OtherName values.
  std::vector<der::Input> other_names;

  // ASCII rfc822names.
  std::vector<std::string_view> rfc822_names;

  // ASCII hostnames.
  std::vector<std::string_view> dns_names;

  // DER-encoded ORAddress values.
  std::vector<der::Input> x400_addresses;

  // DER-encoded Name values (not including the Sequence tag).
  std::vector<der::Input> directory_names;

  // DER-encoded EDIPartyName values.
  std::vector<der::Input> edi_party_names;

  // ASCII URIs.
  std::vector<std::string_view> uniform_resource_identifiers;

  // iPAddresses as sequences of octets in network byte order. This will be
  // populated if the GeneralNames represents a Subject Alternative Name.
  std::vector<fillins::IPAddress> ip_addresses;

  // iPAddress ranges, as <IP, prefix length> pairs. This will be populated
  // if the GeneralNames represents a Name Constraints.
  std::vector<std::pair<fillins::IPAddress, unsigned>> ip_address_ranges;

  // DER-encoded OBJECT IDENTIFIERs.
  std::vector<der::Input> registered_ids;

  // Which name types were present, as a bitfield of GeneralNameTypes.
  int present_name_types = GENERAL_NAME_NONE;
};

// Parses a GeneralName value and adds it to |subtrees|.
// |ip_address_type| specifies how to parse iPAddress names.
// Returns false on failure, and may fill |errors| with additional information.
// |errors| must be non-null.
// TODO(mattm): should this be a method on GeneralNames?
[[nodiscard]] bool ParseGeneralName(
    const der::Input& input,
    GeneralNames::ParseGeneralNameIPAddressType ip_address_type,
    GeneralNames* subtrees,
    CertErrors* errors);

}  // namespace net

#endif  // NET_CERT_PKI_GENERAL_NAMES_H_
