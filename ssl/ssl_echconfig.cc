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

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/hkdf.h>
#include <openssl/ssl.h>

#include "internal.h"


BSSL_NAMESPACE_BEGIN

namespace {
  constexpr size_t kCipherSuiteLen = 2 * sizeof(uint16_t);
}

bool ECHServerConfig::Parse(bool *out_incompatible_version,
                            Span<const uint8_t> raw) {
  *out_incompatible_version = false;

  if (!raw_.CopyFrom(raw)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return false;
  }
  // Read from |raw_| so we can save Spans with the same lifetime as |this|.
  CBS reader(raw_);

  uint16_t version;
  if (!CBS_get_u16(&reader, &version)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    return false;
  }
  // Skip the ECHConfig if it's not a version we support.
  if (version != TLSEXT_TYPE_encrypted_client_hello) {
    *out_incompatible_version = true;
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
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
      CBS_len(&cipher_suites) == 0 ||
      CBS_len(&cipher_suites) % kCipherSuiteLen != 0 ||
      !CBS_get_u16(&ech_config_contents, &max_name_len) ||
      !CBS_get_u16_length_prefixed(&ech_config_contents, &extensions) ||
      CBS_len(&extensions) > 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    return false;
  }

  if (kem_id != EVP_HPKE_DHKEM_X25519_HKDF_SHA256) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_CURVE);
    return false;
  }

  // Parse each cipher suite into |cipher_suites_|
  if (!cipher_suites_.Init(CBS_len(&cipher_suites) / kCipherSuiteLen)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return false;
  }
  size_t num_cipher_suites = 0;
  while (CBS_len(&cipher_suites) > 0) {
    uint16_t kdf_id, aead_id;
    if (!CBS_get_u16(&cipher_suites, &kdf_id) ||
        !CBS_get_u16(&cipher_suites, &aead_id)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
      return false;
    }
    if (kdf_id != EVP_HPKE_HKDF_SHA256 ||
        (aead_id != EVP_HPKE_AEAD_AES_GCM_128 &&
         aead_id != EVP_HPKE_AEAD_AES_GCM_256 &&
         aead_id != EVP_HPKE_AEAD_CHACHA20POLY1305)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_ECH_SERVER_CONFIG_UNSUPPORTED_CIPHERSUITE);
      return false;
    }
    cipher_suites_[num_cipher_suites++] = {kdf_id, aead_id};
  }
  assert(num_cipher_suites == cipher_suites_.size());

  public_name_ = public_name;
  public_key_ = public_key;
  kem_id_ = kem_id;
  max_name_length_ = max_name_len;

  // Precompute the config_id.
  const EVP_MD *hkdf = EVP_HPKE_get_hkdf_md(EVP_HPKE_HKDF_SHA256);
  if (hkdf == nullptr ||  //
      !ConfigID(config_id_sha256_, hkdf)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return false;
  }
  config_id_sha256_present_ = true;
  return true;
}

bool ECHServerConfig::ConfigID(Span<uint8_t> out, const EVP_MD *md) const {
  uint8_t key[EVP_MAX_KEY_LENGTH];
  size_t key_len;
  static const uint8_t info[] = "tls ech config id";
  if (!HKDF_extract(key, &key_len, md, raw_.data(), raw_.size(), nullptr, 0) ||
      !HKDF_expand(out.data(), out.size(), md, key, key_len, info,
                   OPENSSL_ARRAY_SIZE(info) - 1)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return false;
  }
  return true;
}

bool ECHServerConfig::set_secret_key(Span<const uint8_t> secret_key) {
  if (secret_key.size() != sizeof(secret_key_)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    return false;
  }
  OPENSSL_memcpy(secret_key_, secret_key.data(), secret_key.size());
  secret_key_present_ = true;
  return true;
}

BSSL_NAMESPACE_END
