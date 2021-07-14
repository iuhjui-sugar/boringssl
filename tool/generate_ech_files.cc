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

#include <algorithm>
#include <random>
#include <utility>
#include <set>
#include <vector>

#include <assert.h>
#include <string.h>
#include <sys/stat.h>

#if defined(OPENSSL_WINDOWS)
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/hpke.h>
#include <openssl/ssl.h>

#include "internal.h"

static const struct argument kArguments[] = {
    {
        "-out-dir",
        kRequiredArgument,
        "The output directory for ECHConfig values and corresponding private "
        "keys, as well as an ECHConfigList containing each of the ECHConfig "
        "values",
    },
    {
        "-public-names",
        kRequiredArgument,
        "Comma-separated list of public_name values",
    },
    {
        "-maximum-name-lengths",
        kOptionalArgument,
        "Comma-separated list of u16 maximum_name_length values corresponding "
        "to each name in -public-names",
    },
    {
        "-recent-config-ids",
        kOptionalArgument,
        "Comma-separated list of u8 config ID values that must not be reused "
        "when generating new ECHConfig values",
    },
    {
        "",
        kOptionalArgument,
        "",
    },
};

// SplitString tokenizes |str| by splitting on commas. Empty tokens are not
// included in the result.
static std::vector<std::string> SplitString(const std::string &str) {
  const char kDelimiter = ',';
  std::string scratch;
  std::vector<std::string> tokens;
  for (char c : str) {
    if (c != kDelimiter) {
      scratch.push_back(c);
    } else if (!scratch.empty()) {
      tokens.emplace_back(std::move(scratch));
      scratch.clear();
    }
  }
  if (!scratch.empty()) {
    tokens.emplace_back(std::move(scratch));
  }
  return tokens;
}

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

  const std::string &out_dir = args_map["-out-dir"];
  const std::vector<std::string> public_names =
      SplitString(args_map["-public-names"]);

  std::vector<std::string> maximum_name_lengths;
  if (args_map.count("-maximum-name-lengths") != 0) {
    maximum_name_lengths = SplitString(args_map["-maximum-name-lengths"]);
    if (public_names.size() != maximum_name_lengths.size()) {
      fprintf(stderr, "Expected %zu values in -maximum-name-lengths, got %zu\n",
              public_names.size(), maximum_name_lengths.size());
      return false;
    }
  }

  std::set<uint8_t> recent_config_ids;
  if (args_map.count("-recent-config-ids") != 0) {
    for (const std::string &config_id_str :
         SplitString(args_map["-recent-config-ids"])) {
      uint8_t config_id;
      if (!ParseUnsignedInt(&config_id, config_id_str)) {
        fprintf(stderr, "Invalid value in -recent-config-ids: '%s'\n",
                config_id_str.c_str());
        return false;
      }
      recent_config_ids.emplace(config_id);
    }
  }

  // Each ECHConfig will need a randomly-selected config_id that will not
  // conflict with other configs, including any recently-invalidated ECHConfigs
  // that clients or resolvers may still have in their caches.
  if (public_names.size() > 256 - recent_config_ids.size()) {
    fprintf(stderr,
            "Insufficient config_id values remain to generate %zu ECHConfigs\n",
            public_names.size());
    return false;
  }
  uint8_t config_ids[256];
  for (size_t i = 0; i < sizeof(config_ids); i++) {
    config_ids[i] = static_cast<uint8_t>(i);
  }
  size_t num_available_ids = sizeof(config_ids);
  for (uint8_t recent_config_id : recent_config_ids) {
    assert(num_available_ids > public_names.size());
    num_available_ids--;
    std::swap(config_ids[recent_config_id], config_ids[num_available_ids]);
  }
  std::shuffle(config_ids, config_ids + num_available_ids,
               std::default_random_engine());

  struct ECHConfigTemplate {
    std::string public_name;
    uint16_t maximum_name_length;
    uint8_t config_id;
  };
  std::vector<ECHConfigTemplate> templates;
  for (size_t i = 0; i < public_names.size(); i++) {
    uint16_t maximum_name_length = 0;
    if (!maximum_name_lengths.empty() &&
        !ParseUnsignedInt(&maximum_name_length, maximum_name_lengths[i])) {
      fprintf(stderr, "Failed to parse maximum_name_length value from '%s'\n",
              maximum_name_lengths[i].c_str());
      return false;
    }
    assert(i < num_available_ids);
    templates.push_back(
        ECHConfigTemplate{public_names[i], maximum_name_length, config_ids[i]});
  }

  bssl::ScopedCBB cbb;
  CBB body;
  if (!CBB_init(cbb.get(), 256) ||
      !CBB_add_u16_length_prefixed(cbb.get(), &body)) {
    fprintf(stderr, "Failed to serialize the ECHConfigList\n");
    return false;
  }

  // TODO(dmcardle) make cross-platform friendly
  if (mkdir(out_dir.c_str(), 0775) != 0) {
    fprintf(stderr, "Failed to create directory '%s'\n", out_dir.c_str());
    return false;
  }

  for (const ECHConfigTemplate &templ : templates) {
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
    if (!SSL_marshal_ech_config(&ech_config, &ech_config_len, templ.config_id,
                                key.get(), templ.public_name.c_str(),
                                templ.maximum_name_length) ||
        !CBB_add_bytes(&body, ech_config, ech_config_len)) {
      fprintf(stderr, "Failed to serialize the ECHConfigList\n");
      return false;
    }
    bssl::UniquePtr<uint8_t> free_ech_config(ech_config);

    // TODO(dmcardle) make cross-platform friendly
    const std::string ech_config_path =
        out_dir + "/" + templ.public_name + ".echconfig";
    if (!WriteToFile(ech_config_path, ech_config, ech_config_len)) {
      fprintf(stderr, "Failed to write ECHConfig to file\n");
      return false;
    }
    const std::string private_key_path =
        out_dir + "/" + templ.public_name + ".key";
    if (!WriteToFile(private_key_path, private_key_r, private_key_r_len)) {
      fprintf(stderr, "Failed to write private key to file\n");
      return false;
    }
  }
  if (!CBB_flush(cbb.get())) {
    fprintf(stderr, "Failed to serialize the ECHConfigList\n");
    return false;
  }
  const std::string ech_config_list_path = out_dir + "/echconfiglist";
  if (!WriteToFile(ech_config_list_path, CBB_data(cbb.get()),
                   CBB_len(cbb.get()))) {
    fprintf(stderr, "Failed to write ECHConfigList to file\n");
    return false;
  }
  return true;
}
