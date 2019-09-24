/* Copyright (c) 2019, Google Inc.
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

#if !defined(OPENSSL_WINDOWS)
#include <sys/select.h>
#else
OPENSSL_MSVC_PRAGMA(warning(push, 3))
#include <winsock2.h>
OPENSSL_MSVC_PRAGMA(warning(pop))
#endif

#include <openssl/base64.h>
#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "../crypto/internal.h"
#include "internal.h"
#include "transport_common.h"

bool GenerateEsniKeypairs(const std::string &public_name, CBB *out_key_struct,
                          std::vector<CBB> *out_privs);
bool GenerateKeyPair(uint16_t group_id, CBB *pub_key, CBB *priv_key);
bool GenX25519KeyPair(CBB *pub_key, CBB *priv_key);

static const struct argument kArguments[] = {
    {
        "-out-file-prefix",
        kOptionalArgument,
        "The prefix for output filenames. When not specified, output is "
        "written to STDOUT.",
    },
    {
        "-public-name",
        kRequiredArgument,
        "The value of the ESNIKeys public_name field.",
    },
    {
        "",
        kOptionalArgument,
        "",
    },
};

// Serializes a single ESNIKeys into |key_struct|. By default, there will be one
// KeyShareEntry per NamedGroups(). Because NamedGroups() contains more groups
// than kDefaultGroups, there will be keypairs that we ourselves should
// ignore. When |bug_duplicate_group| is true, we will generate an invalid
// ESNIKeys containing 2 KeyShareEntry values for one group.
//
// Parameter |out_key_struct| should already be initialized.
//
// Private keys corresponding to each KeyShareEntry in ESNIKeys are serialized
// in |out_privs|.
bool GenerateEsniKeypairs(const std::string &public_name, CBB *out_key_struct,
                          std::vector<CBB> *out_privs) {
  using namespace bssl;
  CBB public_name_cbb, keys;
  if (!CBB_add_u16(out_key_struct, ESNI_VERSION) ||
      !CBB_add_u16_length_prefixed(out_key_struct, &public_name_cbb) ||
      !CBB_add_bytes(&public_name_cbb,
                     reinterpret_cast<const uint8_t *>(public_name.c_str()),
                     public_name.size()) ||
      !CBB_flush(&public_name_cbb) ||
      !CBB_add_u16_length_prefixed(out_key_struct, &keys)) {
    return false;
  }

  // TODO(dmcardle): add support for SSL_CURVE_SECP256R1 and SSL_CURVE_SECP384R1
  static const uint16_t groups[] = {SSL_CURVE_X25519};

  // Generate a keyshare for each of the groups supported by SSLKeyShare
  for (const uint16_t group_id : groups) {
    CBB kse_bytes;
    if (!CBB_add_u16(&keys, group_id) ||
        !CBB_add_u16_length_prefixed(&keys, &kse_bytes)) {
      return false;
    }

    bssl::ScopedCBB pub_key;
    CBB_init(pub_key.get(), 0);

    out_privs->emplace_back();
    CBB *out_priv = &out_privs->back();
    CBB_init(out_priv, 0);

    if (!GenerateKeyPair(group_id, pub_key.get(), out_priv)) {
      return false;
    }

    // Copy public key into |out_key_struct|
    if (!CBB_add_bytes(&kse_bytes, CBB_data(pub_key.get()),
                       CBB_len(pub_key.get())) ||
        !CBB_flush(&keys)) {
      return false;
    }
  }

  CBB cipher_suites;
  if (!CBB_flush(&keys) ||
      !CBB_add_u16_length_prefixed(out_key_struct, &cipher_suites) ||
      // TODO(dmcardle): pick cipher suite the same way we generate GREASE in
      // ESNI client code.
      !CBB_add_u16(&cipher_suites, 0x1303) || !CBB_flush(&cipher_suites) ||
      !CBB_add_u16(out_key_struct, 32) || !CBB_add_u16(out_key_struct, 0) ||
      !CBB_flush(out_key_struct)) {
    return false;
  }
  return true;
}

// Writes base64-encoded |bytes| to file at |filename|. If |filename| is empty,
// writes labels and base64-encoded to stdout.
static bool PrintBase64(const std::string &label, const std::string &filename,
                        CBB *bytes) {
  bool print_labels = true;
  BIO *file = BIO_new_fp(stdout, 0);
  if (!filename.empty()) {
    print_labels = false;
    file = BIO_new_file(filename.c_str(), "w");
    if (file == nullptr)
      return false;
  }

  // Get the number of bytes for the decoded message + 1 for the trailing NUL.
  size_t base64_len;
  if (!EVP_EncodedLength(&base64_len, CBB_len(bytes))) {
    return false;
  }
  std::vector<uint8_t> encoded;
  encoded.resize(base64_len);

  if (!EVP_EncodeBlock(encoded.data(), CBB_data(bytes), CBB_len(bytes)) ||
      (print_labels &&
       BIO_printf(file, "%s [%zu]: ", label.c_str(), encoded.size()) < 0) ||
      BIO_write_all(file, encoded.data(), encoded.size()) < 0 ||
      (print_labels && BIO_printf(file, "\n") < 0) || !BIO_free(file)) {
    return false;
  }

  return true;
}

static bool DecodeBase64(const std::string &encoded,
                         std::vector<uint8_t> *out) {
  size_t decoded_len, actual_decoded_len;
  if (!EVP_DecodedLength(&decoded_len, encoded.size()))
    return false;
  out->resize(decoded_len);
  if (!EVP_DecodeBase64(out->data(), &actual_decoded_len, out->size(),
                        reinterpret_cast<const uint8_t *>(encoded.data()),
                        encoded.size())) {
    return false;
  }
  return true;
}

bool DecodeEsniKeys(const std::string &encoded, std::vector<uint8_t> *out) {
  return DecodeBase64(encoded, out);
}
bool DecodeEsniPrivs(const std::string &encoded,
                     std::vector<std::vector<uint8_t>> *out_privs) {
  std::vector<uint8_t> decoded;
  if (!DecodeBase64(encoded, &decoded))
    return false;

  CBS privs;
  CBS_init(&privs, decoded.data(), decoded.size() - 1);  // ignore trailing NUL
  while (CBS_len(&privs) > 0) {
    CBS key_bytes;
    if (!CBS_get_u16_length_prefixed(&privs, &key_bytes)) {
      return false;
    }
    std::vector<uint8_t> key(CBS_data(&key_bytes),
                             CBS_data(&key_bytes) + CBS_len(&key_bytes));
    out_privs->push_back(key);
  }
  return true;
}

bool ESNI(const std::vector<std::string> &args) {
  std::map<std::string, std::string> args_map;

  if (!ParseKeyValueArguments(&args_map, args, kArguments)) {
    PrintUsage(kArguments);
    return false;
  }

  std::string esnikeys_filename;
  std::string esniprivs_filename;

  if (args_map.count("-out-file-prefix") != 0) {
    const std::string file_prefix = args_map["-out-file-prefix"];
    esnikeys_filename = file_prefix + ".esnikeys";
    esniprivs_filename = file_prefix + ".esniprivs";
  }

  bssl::ScopedCBB key_struct;
  CBB_init(key_struct.get(), 0);
  std::vector<CBB> priv_keys;
  if (!GenerateEsniKeypairs(args_map["-public-name"], key_struct.get(),
                            &priv_keys)) {
    printf("Failed to generate keypair\n");
    return false;
  }
  PrintBase64("ESNIKeys", esnikeys_filename, key_struct.get());

  bssl::ScopedCBB privkeys_bytes;
  CBB_init(privkeys_bytes.get(), 0);
  for (const CBB &priv : priv_keys) {
    CBB priv_bytes;
    if (!CBB_add_u16_length_prefixed(privkeys_bytes.get(), &priv_bytes) ||
        !CBB_add_bytes(&priv_bytes, CBB_data(&priv), CBB_len(&priv)) ||
        !CBB_flush(privkeys_bytes.get())) {
      return false;
    }
  }
  PrintBase64("ESNI private keys", esniprivs_filename, privkeys_bytes.get());

  for (size_t i = 0; i < priv_keys.size(); i++) {
    CBB_cleanup(&priv_keys[i]);
  }

  return true;
}

// Generates a keypair, writing components into |pub_key| and |priv_key|, both
// of which should already have been initialized with CBB_init.
//
// TODO(dmcardle): implement SSL_CURVE_SECP256R1 and SSL_CURVE_SECP384R1
bool GenerateKeyPair(uint16_t group_id, CBB *pub_key, CBB *priv_key) {
  switch (group_id) {
    case SSL_CURVE_X25519:
      return GenX25519KeyPair(pub_key, priv_key);
    case SSL_CURVE_SECP256R1:
      return false;
    case SSL_CURVE_SECP384R1:
      return false;
    default:
      return false;
  }
}

bool GenX25519KeyPair(CBB *pub_key, CBB *priv_key) {
  uint8_t public_key[32], private_key[32];
  X25519_keypair(public_key, private_key);
  if (!CBB_add_bytes(pub_key, public_key, sizeof(public_key)) ||
      !CBB_add_u16(priv_key, SSL_CURVE_X25519) ||
      !CBB_add_bytes(priv_key, private_key, sizeof(private_key))) {
    return false;
  }

  return true;
}
