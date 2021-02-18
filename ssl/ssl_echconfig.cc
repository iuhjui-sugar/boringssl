/* Copyright (c) 2020, Google Inc.
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

#include <openssl/bytestring.h>
#include <openssl/hkdf.h>

#include "internal.h"


BSSL_NAMESPACE_BEGIN

bool ECHConfig::Parse(bool *out_incompatible_version, Span<const uint8_t> raw) {
  *out_incompatible_version = false;

  if (!raw_.CopyFrom(raw)) {
    return false;
  }
  // Read from |raw_| so we can save Spans with the same lifetime as |this|.
  CBS reader(raw_);

  uint16_t version;
  if (!CBS_get_u16(&reader, &version)) {
    return false;
  }
  // Skip the ECHConfig if it's not a version we support.
  if (version != TLSEXT_TYPE_encrypted_client_hello) {
    *out_incompatible_version = true;
    return false;
  }

  CBS ech_config_contents, public_name, public_key;
  uint16_t kem_id;
  CBS cipher_suites;
  uint16_t max_name_len;
  CBS extensions;
  if (!CBS_get_u16_length_prefixed(&reader, &ech_config_contents) ||
      !CBS_get_u16_length_prefixed(&ech_config_contents, &public_name) ||
      CBS_len(&public_name) == 0 ||
      !CBS_get_u16_length_prefixed(&ech_config_contents, &public_key) ||
      CBS_len(&public_key) == 0 ||
      !CBS_get_u16(&ech_config_contents, &kem_id) ||
      !CBS_get_u16_length_prefixed(&ech_config_contents, &cipher_suites) ||
      CBS_len(&cipher_suites) < 4 ||  //
      CBS_len(&cipher_suites) % 4 != 0 ||
      !CBS_get_u16(&ech_config_contents, &max_name_len) ||
      !CBS_get_u16_length_prefixed(&ech_config_contents, &extensions)) {
    return false;
  }

  const size_t num_suites = CBS_len(&cipher_suites) / (2 * sizeof(uint16_t));
  if (!cipher_suites_.Init(num_suites)) {
    return false;
  }
  for (int cipher_suite_count = 0; CBS_len(&cipher_suites) > 0;
       cipher_suite_count++) {
    if (!CBS_get_u16(&cipher_suites,
                     &cipher_suites_[cipher_suite_count].kdf_id) ||
        !CBS_get_u16(&cipher_suites,
                     &cipher_suites_[cipher_suite_count].aead_id)) {
      return false;
    }
  }

  // Parse the list of ECHConfig extensions.
  GrowableArray<uint16_t> extension_ids;
  while (CBS_len(&extensions) > 0) {
    uint16_t extension_id;
    CBS body;
    if (!CBS_get_u16(&extensions, &extension_id) ||
        !CBS_get_u16_length_prefixed(&extensions, &body)) {
      return false;
    }
    // Unsupported mandatory extensions are a parse failure.
    const uint16_t kMandatoryExtensionMask = 0x8000;
    if (extension_id & kMandatoryExtensionMask) {
      return false;
    }
    // Duplicated extensions IDs are a parse failure.
    if (std::find(extension_ids.begin(), extension_ids.end(), extension_id) !=
        extension_ids.end()) {
      return false;
    }
    extension_ids.Push(extension_id);
  }

  public_name_ = public_name;
  public_key_ = public_key;
  kem_id_ = kem_id;
  max_name_length_ = max_name_len;

  // Precompute the config_id.
  const EVP_MD *hkdf = EVP_HPKE_get_hkdf_md(EVP_HPKE_HKDF_SHA256);
  if (hkdf == nullptr) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return false;
  }
  if (!ConfigID(config_id_sha256_, hkdf)) {
    return false;
  }
  config_id_sha256_present_ = true;
  return true;
}

bool ECHConfig::ConfigID(Span<uint8_t> out, const EVP_MD *md) const {
  uint8_t key[EVP_MAX_KEY_LENGTH];
  size_t key_len;
  static const uint8_t info[] = "tls ech config id";
  if (!HKDF_extract(key, &key_len, md, raw_.data(), raw_.size(), nullptr, 0) ||
      !HKDF_expand(out.data(), out.size(), md, key, key_len, info,
                   OPENSSL_ARRAY_SIZE(info) - 1)) {
    return false;
  }
  return true;
}

BSSL_NAMESPACE_END
