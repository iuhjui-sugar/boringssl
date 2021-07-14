/* Copyright (c) 2021, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */
#include <openssl/base.h>

#include <stdio.h>

#include <vector>

#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/hpke.h>
#include <openssl/ssl.h>

#include "internal.h"

static const struct argument kArguments[] = {
    {
        "-public-name",
        kRequiredArgument,
        "The public_name for the new ECHConfig",
    },
    {
        "-config-id",
        kRequiredArgument,
        "The u8 config_id for the new ECHConfig",
    },
    {
        "-maximum-name-length",
        kOptionalArgument,
        "Optional u16 maximum_name_length value for the new ECHConfig",
    },
    {
        "",
        kOptionalArgument,
        "",
    },
};

template <typename T>
static bool ParseUnsignedInt(T *out, const std::string &str) {
  T value = 0;
  for (char c : str) {
    if (c < '0' || c > '9' ||
        value > (std::numeric_limits<T>::max() - (c - '0')) / 10) {
      return false;
    }
    value = value * 10 + (c - '0');
  }
  *out = value;
  return true;
}

bool GenerateECHFiles(const std::vector<std::string> &args) {
  std::map<std::string, std::string> args_map;
  if (!ParseKeyValueArguments(&args_map, args, kArguments)) {
    PrintUsage(kArguments);
    return false;
  }

  const std::string& public_name = args_map["-public-name"];

  uint8_t config_id;
  if (!ParseUnsignedInt(&config_id, args_map["-config-id"])) {
    fprintf(stderr, "Error parsing -config-id argument\n");
    return false;
  }

  uint16_t maximum_name_length = 0;
  if (args_map.count("-maximum-name-length") != 0 &&
      !ParseUnsignedInt(&maximum_name_length,
                        args_map["-maximum-name-length"])) {
    fprintf(stderr, "Error parsing -maximum-name-length argument\n");
    return false;
  }

  bssl::ScopedEVP_HPKE_KEY key;
  uint8_t public_key_r[X25519_PUBLIC_VALUE_LEN];
  uint8_t private_key_r[X25519_PRIVATE_KEY_LEN];
  size_t public_key_r_len, private_key_r_len;
  if (!EVP_HPKE_KEY_generate(key.get(), EVP_hpke_x25519_hkdf_sha256()) ||
      !EVP_HPKE_KEY_public_key(key.get(), public_key_r, &public_key_r_len,
                               sizeof(public_key_r)) ||
      !EVP_HPKE_KEY_private_key(key.get(), private_key_r, &private_key_r_len,
                                sizeof(private_key_r))) {
    fprintf(stderr, "Failed to generate the HPKE keypair\n");
    return false;
  }

  uint8_t *ech_config = nullptr;
  size_t ech_config_len = 0;
  if (!SSL_marshal_ech_config(&ech_config, &ech_config_len, config_id,
                              key.get(), public_name.c_str(),
                              maximum_name_length)) {
    fprintf(stderr, "Failed to serialize the ECHConfigList\n");
    return false;
  }
  bssl::UniquePtr<uint8_t> free_ech_config(ech_config);

  bssl::ScopedCBB cbb;
  CBB body;
  if (!CBB_init(cbb.get(), ech_config_len + sizeof(uint16_t)) ||
      !CBB_add_u16_length_prefixed(cbb.get(), &body) ||
      !CBB_add_bytes(&body, ech_config, ech_config_len) ||
      !CBB_flush(cbb.get())) {
    fprintf(stderr, "Failed to serialize the ECHConfigList\n");
    return false;
  }
  if (!WriteToFile(public_name + ".ech_config_list", CBB_data(cbb.get()),
                   CBB_len(cbb.get())) ||
      !WriteToFile(public_name + ".ech_config", ech_config, ech_config_len) ||
      !WriteToFile(public_name + ".key", private_key_r, private_key_r_len)) {
    fprintf(stderr, "Failed to write ECHConfig or private key to file\n");
    return false;
  }
  return true;
}
