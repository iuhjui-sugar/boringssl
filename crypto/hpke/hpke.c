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

#include <assert.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>

#include "../internal.h"
#include "internal.h"

// HPKE KEM scheme IDs.
#define EVP_HPKE_DHKEM_X25519_HKDF_SHA256 0x0020
// HPKE KDF IDs.
#define HPKE_HKDF_SHA256 0x0001
// HPKE AEAD IDs.
#define HPKE_AEAD_AES_GCM_128 0x0001

#define KEM_CONTEXT_LEN (2 * X25519_PUBLIC_VALUE_LEN)
#define HKDF_SHA256_NH 32
#define AES_GCM_128_NK 16
#define AES_GCM_128_NN 12

static const uint8_t kHpkeRfcId[] = {'R', 'F', 'C', 'X', 'X', 'X', 'X', ' '};

typedef enum evp_hpke_mode {
  EVP_HPKE_MODE_BASE = 0,  // We only support |HPKE_MODE_BASE|.
  EVP_HPKE_MODE_PSK = 1,
  EVP_HPKE_MODE_AUTH = 2,
  EVP_HPKE_MODE_AUTH_PSK = 3,
} evp_hpke_mode;

static int hpke_labeled_extract(EVP_HPKE_CTX *hpke, uint8_t *out_key,
                                size_t *out_len, const uint8_t *salt,
                                size_t salt_len, const uint8_t *label,
                                size_t label_len, const uint8_t *ikm,
                                size_t ikm_len) {
  CBB labeled_ikm;
  if (!CBB_init(&labeled_ikm, sizeof(kHpkeRfcId) + label_len + ikm_len)) {
    return 0;
  }
  if (!CBB_add_bytes(&labeled_ikm, kHpkeRfcId, sizeof(kHpkeRfcId)) ||
      !CBB_add_bytes(&labeled_ikm, label, label_len) ||
      !CBB_add_bytes(&labeled_ikm, ikm, ikm_len) ||
      !HKDF_extract(out_key, out_len, hpke->hkdf_md, CBB_data(&labeled_ikm),
                    CBB_len(&labeled_ikm), salt, salt_len)) {
    CBB_cleanup(&labeled_ikm);
    return 0;
  }

  CBB_cleanup(&labeled_ikm);
  return 1;
}

static int hpke_labeled_expand(EVP_HPKE_CTX *hpke, uint8_t *out_key,
                               size_t out_len, const uint8_t *prk,
                               size_t prk_len, const uint8_t *label,
                               size_t label_len, const uint8_t *info,
                               size_t info_len) {
  CBB labeled_info;
  if (!CBB_init(&labeled_info,
                sizeof(uint16_t) + sizeof(kHpkeRfcId) + label_len + info_len)) {
    return 0;
  }
  if (!CBB_add_u16(&labeled_info, out_len) ||
      !CBB_add_bytes(&labeled_info, kHpkeRfcId, sizeof(kHpkeRfcId)) ||
      !CBB_add_bytes(&labeled_info, label, label_len) ||
      !CBB_add_bytes(&labeled_info, info, info_len) ||
      !HKDF_expand(out_key, out_len, hpke->hkdf_md, prk, prk_len,
                   CBB_data(&labeled_info), CBB_len(&labeled_info))) {
    CBB_cleanup(&labeled_info);
    return 0;
  }
  CBB_cleanup(&labeled_info);
  return 1;
}

static int hpke_extract_and_expand(EVP_HPKE_CTX *hpke, uint8_t *out_key,
                                   size_t out_len,
                                   const uint8_t dh[X25519_PUBLIC_VALUE_LEN],
                                   const uint8_t kem_context[KEM_CONTEXT_LEN]) {
  const uint8_t kExtractLabel[] = {'d', 'h'};
  const uint8_t kExpandLabel[] = {'p', 'r', 'k'};

  uint8_t prk[EVP_MAX_MD_SIZE];
  size_t prk_len;
  const uint8_t kZeroSalt[HKDF_SHA256_NH] = {0};
  if (!hpke_labeled_extract(hpke, prk, &prk_len, kZeroSalt, sizeof(kZeroSalt),
                            kExtractLabel, sizeof(kExtractLabel), dh,
                            X25519_PUBLIC_VALUE_LEN)) {
    return 0;
  }
  if (!hpke_labeled_expand(hpke, out_key, out_len, prk, prk_len, kExpandLabel,
                           sizeof(kExpandLabel), kem_context,
                           KEM_CONTEXT_LEN)) {
    return 0;
  }
  return 1;
}

static int hpke_key_schedule(EVP_HPKE_CTX *hpke, const uint8_t *zz,
                             size_t zz_len, const uint8_t *info,
                             size_t info_len) {
  const uint8_t kZeroPubKey[X25519_PUBLIC_VALUE_LEN] = {0};
  const uint8_t kZeroSalt[HKDF_SHA256_NH] = {0};

  // pskID_hash = LabeledExtract(zero(Nh), "pskID_hash", info_hash)
  const uint8_t kPskIdHashLabel[] = {'p', 's', 'k', 'I', 'D',
                                     '_', 'h', 'a', 's', 'h'};
  uint8_t psk_id_hash[EVP_MAX_MD_SIZE];
  size_t psk_id_hash_len;
  if (!hpke_labeled_extract(hpke, psk_id_hash, &psk_id_hash_len, kZeroSalt,
                            sizeof(kZeroSalt), kPskIdHashLabel,
                            sizeof(kPskIdHashLabel), NULL, 0)) {
    return 0;
  }

  // info_hash = LabeledExtract(zero(Nh), "info", info)
  const uint8_t kInfoHashLabel[] = {'i', 'n', 'f', 'o'};
  uint8_t info_hash[EVP_MAX_MD_SIZE];
  size_t info_hash_len;
  if (!hpke_labeled_extract(hpke, info_hash, &info_hash_len, kZeroSalt,
                            sizeof(kZeroSalt), kInfoHashLabel,
                            sizeof(kInfoHashLabel), info, info_len)) {
    return 0;
  }

  // context = concat(ciphersuite, mode, pskID_hash, info_hash)
  uint8_t context[3 * sizeof(uint16_t) + sizeof(uint8_t) + 2 * EVP_MAX_MD_SIZE];
  CBB context_cbb;
  if (!CBB_init_fixed(&context_cbb, context, sizeof(context))) {
    return 0;
  }
  if (!CBB_add_u16(&context_cbb, EVP_HPKE_DHKEM_X25519_HKDF_SHA256) ||
      !CBB_add_u16(&context_cbb, HPKE_HKDF_SHA256) ||
      !CBB_add_u16(&context_cbb, HPKE_AEAD_AES_GCM_128) ||
      !CBB_add_u8(&context_cbb, EVP_HPKE_MODE_BASE) ||
      !CBB_add_bytes(&context_cbb, psk_id_hash, psk_id_hash_len) ||
      !CBB_add_bytes(&context_cbb, info_hash, info_hash_len)) {
    goto cleanup_fail;
  }

  // psk_hash = LabeledExtract(zero(Nh), "psk_hash", psk)
  const uint8_t kPskHashLabel[] = {'p', 's', 'k', '_', 'h', 'a', 's', 'h'};
  uint8_t psk_hash[EVP_MAX_MD_SIZE];
  size_t psk_hash_len;
  if (!hpke_labeled_extract(hpke, psk_hash, &psk_hash_len, kZeroSalt,
                            sizeof(kZeroSalt), kPskHashLabel,
                            sizeof(kPskHashLabel), kZeroPubKey,
                            sizeof(kZeroPubKey))) {
    goto cleanup_fail;
  }

  // secret = LabeledExtract(psk_hash, "zz", zz)
  const uint8_t kSecretLabel[] = {'z', 'z'};
  uint8_t secret[EVP_MAX_MD_SIZE];
  size_t secret_len;
  if (!hpke_labeled_extract(hpke, secret, &secret_len, psk_hash, psk_hash_len,
                            kSecretLabel, sizeof(kSecretLabel), zz, zz_len)) {
    goto cleanup_fail;
  }

  // key = LabeledExpand(secret, "key", context, Nk)
  const uint8_t kKeyLabel[] = {'k', 'e', 'y'};
  uint8_t key[AES_GCM_128_NK];
  if (!hpke_labeled_expand(hpke, key, AES_GCM_128_NK, secret, secret_len,
                           kKeyLabel, sizeof(kKeyLabel), CBB_data(&context_cbb),
                           CBB_len(&context_cbb))) {
    goto cleanup_fail;
  }

  // Initialize the HPKE context's AEAD context, storing a copy of |key|.
  if (!EVP_AEAD_CTX_init(&hpke->aead, EVP_aead_aes_128_gcm(), key, sizeof(key),
                         EVP_AEAD_DEFAULT_TAG_LENGTH, NULL)) {
    goto cleanup_fail;
  }

  // nonce = LabeledExpand(secret, "nonce", context, Nn)
  const uint8_t kNonceLabel[] = {'n', 'o', 'n', 'c', 'e'};
  if (!hpke_labeled_expand(hpke, hpke->nonce, AES_GCM_128_NN, secret,
                           secret_len, kNonceLabel, sizeof(kNonceLabel),
                           CBB_data(&context_cbb), CBB_len(&context_cbb))) {
    goto cleanup_fail;
  }

  // exporter_secret = LabeledExpand(secret, "exp", conetxt, Nh)
  const uint8_t kExporterSecretLabel[] = {'e', 'x', 'p'};
  if (!hpke_labeled_expand(hpke, hpke->exporter_secret, HKDF_SHA256_NH, secret,
                           secret_len, kExporterSecretLabel,
                           sizeof(kExporterSecretLabel), CBB_data(&context_cbb),
                           CBB_len(&context_cbb))) {
    goto cleanup_fail;
  }

  CBB_cleanup(&context_cbb);
  return 1;

cleanup_fail:
  CBB_cleanup(&context_cbb);
  return 0;
}

int EVP_HPKE_CTX_setup_base_x25519_s(
    EVP_HPKE_CTX *hpke, uint8_t *out_enc,
    const uint8_t peer_public_value[X25519_PUBLIC_VALUE_LEN],
    const uint8_t *info, size_t info_len) {
  // Encap(peer_public_value):
  uint8_t ephemeral_private[X25519_PRIVATE_KEY_LEN];
  X25519_keypair(out_enc, ephemeral_private);
  uint8_t dh[X25519_PUBLIC_VALUE_LEN];
  X25519_public_from_private(dh, ephemeral_private);
  uint8_t kem_context[KEM_CONTEXT_LEN];
  OPENSSL_memcpy(kem_context, out_enc, X25519_PUBLIC_VALUE_LEN);
  OPENSSL_memcpy(kem_context + X25519_PUBLIC_VALUE_LEN, peer_public_value,
                 X25519_PUBLIC_VALUE_LEN);
  uint8_t zz[SHA256_DIGEST_LENGTH];
  if (!hpke_extract_and_expand(hpke, zz, sizeof(zz), dh, kem_context)) {
    return 0;
  }

  if (!hpke_key_schedule(hpke, zz, sizeof(zz), info, info_len)) {
    return 0;
  }

  return 1;
}

void EVP_HPKE_CTX_init(EVP_HPKE_CTX *ctx) {
  // The KEM's KDF
  ctx->kem_hkdf_md = EVP_sha256();

  // KDF
  ctx->hkdf_md = EVP_sha256();

  // AEAD
  EVP_AEAD_CTX_zero(&ctx->aead);

  // Remaining context.
  OPENSSL_memset(&ctx->nonce, 0, sizeof(ctx->nonce));
  OPENSSL_memset(&ctx->exporter_secret, 0, sizeof(ctx->exporter_secret));
  ctx->seq = 0;
}

void EVP_HPKE_CTX_cleanup(EVP_HPKE_CTX *ctx) {}
