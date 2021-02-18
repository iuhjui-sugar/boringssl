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
#include <openssl/curve25519.h>
#include <openssl/err.h>
#include <openssl/hkdf.h>
#include <openssl/ssl.h>

#include "internal.h"

#if defined(OPENSSL_MSAN)
#define NO_SANITIZE_MEMORY __attribute__((no_sanitize("memory")))
#else
#define NO_SANITIZE_MEMORY
#endif

BSSL_NAMESPACE_BEGIN

static constexpr size_t kCipherSuiteLen = 2 * sizeof(uint16_t);

// ssl_client_hello_write_without_extensions serializes |client_hello| into
// |out|, omitting the length-prefixed extensions. It serializes individual
// fields, starting with |client_hello->version|, and ignores the
// |client_hello->client_hello| field. It returns true on success and false on
// failure.
static bool ssl_client_hello_write_without_extensions(
    const SSL_CLIENT_HELLO *client_hello, CBB *out) {
  if (!CBB_add_u16(out, client_hello->version) ||
      !CBB_add_bytes(out, client_hello->random, client_hello->random_len) ||
      !CBB_add_u8(out, client_hello->session_id_len) ||
      !CBB_add_bytes(out, client_hello->session_id,
                     client_hello->session_id_len) ||
      !CBB_add_u16(out, client_hello->cipher_suites_len) ||
      !CBB_add_bytes(out, client_hello->cipher_suites,
                     client_hello->cipher_suites_len) ||
      !CBB_add_u8(out, client_hello->compression_methods_len) ||
      !CBB_add_bytes(out, client_hello->compression_methods,
                     client_hello->compression_methods_len)) {
    return false;
  }
  return true;
}

bool ssl_decode_client_hello_inner(
    SSL *ssl, uint8_t *out_alert, Array<uint8_t> *out_client_hello_inner,
    Span<const uint8_t> encoded_client_hello_inner,
    const SSL_CLIENT_HELLO *client_hello_outer) {
  SSL_CLIENT_HELLO client_hello_inner;
  if (!ssl_client_hello_init(ssl, &client_hello_inner,
                             encoded_client_hello_inner)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    return false;
  }

  // TLS 1.3 ClientHellos must have extensions. The definition of
  // EncodedClientHelloInner says the session_id is empty.
  if (client_hello_inner.extensions_len == 0 ||
      client_hello_inner.session_id_len != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    return false;
  }
  // Use the ClientHelloOuter's session_id.
  client_hello_inner.session_id = client_hello_outer->session_id;
  client_hello_inner.session_id_len = client_hello_outer->session_id_len;

  // Begin serializing a message containing the ClientHelloInner in |cbb|.
  ScopedCBB cbb;
  CBB body, extensions;
  if (!ssl->method->init_message(ssl, cbb.get(), &body, SSL3_MT_CLIENT_HELLO) ||
      !ssl_client_hello_write_without_extensions(&client_hello_inner, &body) ||
      !CBB_add_u16_length_prefixed(&body, &extensions)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return false;
  }

  // Sort the extensions in ClientHelloOuter, so ech_outer_extensions may be
  // processed in O(n*log(n)) time, rather than O(n^2).

  // Count ClientHelloOuter's extensions.
  size_t num_extensions = 0;
  CBS unsorted_extensions(MakeConstSpan(client_hello_outer->extensions,
                                        client_hello_outer->extensions_len));
  while (CBS_len(&unsorted_extensions) > 0) {
    uint16_t extension_unused;
    CBS body_unused;
    if (!CBS_get_u16(&unsorted_extensions, &extension_unused) ||
        !CBS_get_u16_length_prefixed(&unsorted_extensions, &body_unused)) {
      // The ClientHelloOuter was already parsed, so this should not fail.
      OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
      return false;
    }
    num_extensions++;
  }

  struct Extension {
    uint16_t extension = 0;
    Span<const uint8_t> body;
    bool copied = false;
  };

  // compare_extension is a comparator for Extension. It is compatible with
  // qsort and bsearch.
  //
  // Disable MSan for this lambda. MSan's libc interceptors do not handle
  // |bsearch|. See b/182583130.
  auto compare_extension = [](const void *a, const void *b)
                               NO_SANITIZE_MEMORY -> int {
    const Extension *extension_a = reinterpret_cast<const Extension *>(a);
    const Extension *extension_b = reinterpret_cast<const Extension *>(b);
    if (extension_a->extension < extension_b->extension) {
      return -1;
    } else if (extension_a->extension > extension_b->extension) {
      return 1;
    }
    return 0;
  };
  // Allocate and fill an array of Extension.
  Array<Extension> sorted_extensions;
  if (!sorted_extensions.Init(num_extensions)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return false;
  }
  num_extensions = 0;
  CBS_init(&unsorted_extensions, client_hello_outer->extensions,
           client_hello_outer->extensions_len);
  while (CBS_len(&unsorted_extensions) > 0) {
    Extension *extension = &sorted_extensions[num_extensions++];
    CBS extension_body;
    if (!CBS_get_u16(&unsorted_extensions, &extension->extension) ||
        !CBS_get_u16_length_prefixed(&unsorted_extensions, &extension_body)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
      return false;
    }
    extension->body = extension_body;
    extension->copied = false;
  }

  qsort(sorted_extensions.data(), sorted_extensions.size(), sizeof(Extension),
        compare_extension);

  // Reconstitute the ClientHelloInner's extensions into |extensions|.
  CBS inner_extensions(MakeConstSpan(client_hello_inner.extensions,
                                     client_hello_inner.extensions_len));
  while (CBS_len(&inner_extensions) > 0) {
    uint16_t extension_id;
    CBS extension_body;
    if (!CBS_get_u16(&inner_extensions, &extension_id) ||
        !CBS_get_u16_length_prefixed(&inner_extensions, &extension_body)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
      return false;
    }
    // Unless it is ech_outer_extensions, just copy the extension exactly.
    if (extension_id != TLSEXT_TYPE_ech_outer_extensions) {
      if (!CBB_add_u16(&extensions, extension_id) ||
          !CBB_add_u16(&extensions, CBS_len(&extension_body)) ||
          !CBB_add_bytes(&extensions, CBS_data(&extension_body),
                         CBS_len(&extension_body))) {
        OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
        return false;
      }
      continue;
    }

    // Replace ech_outer_extensions with the corresponding outer extensions.
    CBS outer_extensions;
    if (!CBS_get_u8_length_prefixed(&extension_body, &outer_extensions) ||
        CBS_len(&outer_extensions) % sizeof(uint16_t) != 0 ||
        CBS_len(&extension_body) != 0) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
      return false;
    }

    while (CBS_len(&outer_extensions) > 0) {
      uint16_t extension_needed;
      if (!CBS_get_u16(&outer_extensions, &extension_needed)) {
        OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
        return false;
      }
      if (extension_needed == TLSEXT_TYPE_encrypted_client_hello) {
        *out_alert = SSL_AD_ILLEGAL_PARAMETER;
        OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
        return false;
      }
      // Use binary search to find the extension for |extension_needed|.
      Extension key;
      key.extension = extension_needed;
      Extension *result = reinterpret_cast<Extension *>(
          bsearch(&key, sorted_extensions.data(), sorted_extensions.size(),
                  sizeof(Extension), compare_extension));
      // If the extension is missing, abort with illegal_parameter alert.
      if (result == nullptr) {
        *out_alert = SSL_AD_ILLEGAL_PARAMETER;
        OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
        return false;
      }

      // If we've already copied this extension, ech_outer_extensions must have
      // referenced it twice.
      if (result->copied) {
        OPENSSL_PUT_ERROR(SSL, SSL_R_DUPLICATE_EXTENSION);
        return false;
      }
      result->copied = true;

      if (!CBB_add_u16(&extensions, extension_needed) ||
          !CBB_add_u16(&extensions, result->body.size()) ||
          !CBB_add_bytes(&extensions, result->body.data(),
                         result->body.size())) {
        OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
        return false;
      }
    }
  }

  // Finish the ClientHelloInner and store it on |out_client_hello_inner|.
  if (!ssl->method->finish_message(ssl, cbb.get(), out_client_hello_inner)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return false;
  }
  return true;
}

bool ssl_client_hello_decrypt(
    EVP_HPKE_CTX *hpke_ctx, Array<uint8_t> *out_encoded_client_hello_inner,
    bool *out_is_decrypt_error, const SSL_CLIENT_HELLO *client_hello_outer,
    ECHServerConfig::ECHCipherSuite suite, Span<const uint8_t> config_id,
    Span<const uint8_t> enc, Span<const uint8_t> payload) {
  *out_is_decrypt_error = false;

  // Compute the ClientHello portion of the ClientHelloOuterAAD value. See
  // draft-ietf-tls-esni-09, section 5.2.
  ScopedCBB ch_outer_aad_cbb;
  CBB config_id_cbb, enc_cbb, outer_hello_cbb, extensions_cbb;
  if (!CBB_init(ch_outer_aad_cbb.get(), 0) ||
      !CBB_add_u16(ch_outer_aad_cbb.get(), suite.kdf_id) ||
      !CBB_add_u16(ch_outer_aad_cbb.get(), suite.aead_id) ||
      !CBB_add_u8_length_prefixed(ch_outer_aad_cbb.get(), &config_id_cbb) ||
      !CBB_add_bytes(&config_id_cbb, config_id.data(), config_id.size()) ||
      !CBB_add_u16_length_prefixed(ch_outer_aad_cbb.get(), &enc_cbb) ||
      !CBB_add_bytes(&enc_cbb, enc.data(), enc.size()) ||
      !CBB_add_u24_length_prefixed(ch_outer_aad_cbb.get(), &outer_hello_cbb) ||
      !ssl_client_hello_write_without_extensions(client_hello_outer,
                                                 &outer_hello_cbb) ||
      !CBB_add_u16_length_prefixed(&outer_hello_cbb, &extensions_cbb)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return false;
  }

  CBS extensions_reader(MakeConstSpan(client_hello_outer->extensions,
                                      client_hello_outer->extensions_len));
  while (CBS_len(&extensions_reader) > 0) {
    uint16_t extension_id;
    CBS extension_body;
    if (!CBS_get_u16(&extensions_reader, &extension_id) ||
        !CBS_get_u16_length_prefixed(&extensions_reader, &extension_body)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
      return false;
    }
    if (extension_id == TLSEXT_TYPE_encrypted_client_hello) {
      continue;
    }
    if (!CBB_add_u16(&extensions_cbb, extension_id) ||
        !CBB_add_u16(&extensions_cbb, CBS_len(&extension_body)) ||
        !CBB_add_bytes(&extensions_cbb, CBS_data(&extension_body),
                       CBS_len(&extension_body))) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      return false;
    }
  }
  if (!CBB_flush(ch_outer_aad_cbb.get())) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return false;
  }

  // Attempt to decrypt into |out_encoded_client_hello_inner|.
  if (!out_encoded_client_hello_inner->Init(payload.size())) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return false;
  }
  size_t encoded_client_hello_inner_len;
  if (!EVP_HPKE_CTX_open(hpke_ctx, out_encoded_client_hello_inner->data(),
                         &encoded_client_hello_inner_len,
                         out_encoded_client_hello_inner->size(), payload.data(),
                         payload.size(), CBB_data(ch_outer_aad_cbb.get()),
                         CBB_len(ch_outer_aad_cbb.get()))) {
    *out_is_decrypt_error = true;
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECRYPTION_FAILED);
    return false;
  }
  out_encoded_client_hello_inner->Shrink(encoded_client_hello_inner_len);
  return true;
}


bool ECHServerConfig::Init(Span<const uint8_t> raw,
                           Span<const uint8_t> secret_key,
                           bool is_retry_config) {
  is_retry_config_ = is_retry_config;

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
  // Check that we know how to parse this version before proceeding.
  if (version != TLSEXT_TYPE_encrypted_client_hello) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNSUPPORTED_ECH_SERVER_CONFIG);
    return false;
  }

  CBS ech_config_contents, public_name, public_key, cipher_suites, extensions;
  uint16_t kem_id, max_name_len;
  if (!CBS_get_u16_length_prefixed(&reader, &ech_config_contents) ||
      !CBS_get_u16_length_prefixed(&ech_config_contents, &public_name) ||
      CBS_len(&public_name) == 0 ||
      !CBS_get_u16_length_prefixed(&ech_config_contents, &public_key) ||
      CBS_len(&public_key) == 0 ||
      !CBS_get_u16(&ech_config_contents, &kem_id) ||
      !CBS_get_u16_length_prefixed(&ech_config_contents, &cipher_suites) ||
      CBS_len(&cipher_suites) == 0 ||
      !CBS_get_u16(&ech_config_contents, &max_name_len) ||
      !CBS_get_u16_length_prefixed(&ech_config_contents, &extensions) ||
      CBS_len(&ech_config_contents) != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    return false;
  }
  // We only support one KEM, and the KEM decides the length of |public_key|.
  if (CBS_len(&public_key) != X25519_PUBLIC_VALUE_LEN ||
      kem_id != EVP_HPKE_DHKEM_X25519_HKDF_SHA256) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNSUPPORTED_ECH_SERVER_CONFIG);
    return false;
  }
  // This parser fails when it encounters any bytes it does not understand. We
  // support zero ECHConfig extensions, so nonempty |extensions| is an error.
  if (CBS_len(&extensions) != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_ECH_SERVER_CONFIG_UNSUPPORTED_EXTENSION);
    return false;
  }

  // Parse each cipher suite into |cipher_suites_|.
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
    // This parser fails when it encounters any bytes it does not understand. If
    // the config lists any unsupported cipher suites, that is a parse error.
    if (kdf_id != EVP_HPKE_HKDF_SHA256 ||
        (aead_id != EVP_HPKE_AEAD_AES_GCM_128 &&
         aead_id != EVP_HPKE_AEAD_AES_GCM_256 &&
         aead_id != EVP_HPKE_AEAD_CHACHA20POLY1305)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_UNSUPPORTED_ECH_SERVER_CONFIG);
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

  // Now that we have parsed |raw|, validate and save a copy of |secret_key|.

  if (secret_key.size() != X25519_PRIVATE_KEY_LEN) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    return false;
  }
  uint8_t expected_public_key[X25519_PUBLIC_VALUE_LEN];
  X25519_public_from_private(expected_public_key, secret_key.data());
  if (public_key_ != expected_public_key) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_ECH_SERVER_CONFIG_AND_PRIVATE_KEY_MISMATCH);
    return false;
  }
  assert(sizeof(secret_key_) == secret_key.size());
  OPENSSL_memcpy(secret_key_, secret_key.data(), secret_key.size());
  secret_key_present_ = true;

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

BSSL_NAMESPACE_END
