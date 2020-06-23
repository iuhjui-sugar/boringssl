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
#include <openssl/aead.h>
#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>

#include "../internal.h"
#include "internal.h"

#define DHKEM_X25519_HKDF_SHA256_NZZ 32
#define DHKEM_X25519_HKDF_SHA256_NENC 32
#define DHKEM_X25519_HKDF_SHA256_NPK 32

#define KEM_CONTEXT_LEN (2 * X25519_PUBLIC_VALUE_LEN)
#define HKDF_SHA256_NH 32

// HPKE KEM scheme IDs.
#define EVP_HPKE_DHKEM_X25519_HKDF_SHA256 0x0020
// HPKE KDF IDs.
#define HPKE_HKDF_SHA256 0x0001

// TODO(dmcardle): Delete this function and calls when ready to commit.
static void PrintActual(const char *debug_label, const uint8_t *data,
                        size_t data_len) {
  printf("actual [%zu bytes] %s:\n", data_len, debug_label);
  for (size_t i = 0; i < data_len; i++) {
    printf("%.2x", data[i]);
  }
  printf("\n");
}

static const char kHpkeRfcId[] = "RFCXXXX ";

static int add_label_string(CBB *cbb, const char *label) {
  return CBB_add_bytes(cbb, (const uint8_t *)label, strlen(label));
}

typedef enum evp_hpke_mode {
  EVP_HPKE_MODE_BASE = 0,  // We only support |HPKE_MODE_BASE|.
  EVP_HPKE_MODE_PSK = 1,
  EVP_HPKE_MODE_AUTH = 2,
  EVP_HPKE_MODE_AUTH_PSK = 3,
} evp_hpke_mode;

static int hpke_labeled_extract(const EVP_HPKE_CTX *hpke, uint8_t *out_key,
                                size_t *out_len, const uint8_t *salt,
                                size_t salt_len, const char *label,
                                const uint8_t *ikm, size_t ikm_len) {
  CBB labeled_ikm;
  int ok =
      (CBB_init(&labeled_ikm, strlen(kHpkeRfcId) + strlen(label) + ikm_len) &&
       add_label_string(&labeled_ikm, kHpkeRfcId) &&
       add_label_string(&labeled_ikm, label) &&
       CBB_add_bytes(&labeled_ikm, ikm, ikm_len) &&
       HKDF_extract(out_key, out_len, hpke->hkdf_md, CBB_data(&labeled_ikm),
                    CBB_len(&labeled_ikm), salt, salt_len));
  CBB_cleanup(&labeled_ikm);
  return ok;
}

static int hpke_labeled_expand(const EVP_HPKE_CTX *hpke, uint8_t *out_key,
                               size_t out_len, const uint8_t *prk,
                               size_t prk_len, const char *label,
                               const uint8_t *info, size_t info_len) {
  CBB labeled_info;
  int ok = (CBB_init(&labeled_info, sizeof(uint16_t) + strlen(kHpkeRfcId) +
                                        strlen(label) + info_len) &&
            CBB_add_u16(&labeled_info, out_len) &&
            add_label_string(&labeled_info, kHpkeRfcId) &&
            add_label_string(&labeled_info, label) &&
            CBB_add_bytes(&labeled_info, info, info_len) &&
            HKDF_expand(out_key, out_len, hpke->hkdf_md, prk, prk_len,
                        CBB_data(&labeled_info), CBB_len(&labeled_info)));
  CBB_cleanup(&labeled_info);
  return ok;
}

static int hpke_extract_and_expand(const EVP_HPKE_CTX *hpke, uint8_t *out_key,
                                   size_t out_len,
                                   const uint8_t dh[X25519_PUBLIC_VALUE_LEN],
                                   const uint8_t kem_context[KEM_CONTEXT_LEN]) {
  static const char kDHExtractLabel[] = "dh";
  uint8_t prk[EVP_MAX_MD_SIZE];
  size_t prk_len;
  const uint8_t kZeroSalt[HKDF_SHA256_NH] = {0};
  if (!hpke_labeled_extract(hpke, prk, &prk_len, kZeroSalt, sizeof(kZeroSalt),
                            kDHExtractLabel, dh, X25519_PUBLIC_VALUE_LEN)) {
    return 0;
  }
  static const char kPRKExpandLabel[] = "prk";
  if (!hpke_labeled_expand(hpke, out_key, out_len, prk, prk_len,
                           kPRKExpandLabel, kem_context, KEM_CONTEXT_LEN)) {
    return 0;
  }
  return 1;
}

static int hpke_key_schedule(EVP_HPKE_CTX *hpke, uint16_t aead_id,
                             const uint8_t *zz, size_t zz_len,
                             const uint8_t *info, size_t info_len) {
  // Attempt to get an EVP_AEAD*.
  const EVP_AEAD *aead = NULL;
  if (aead_id == HPKE_AEAD_AES_GCM_128) {
    aead = EVP_aead_aes_128_gcm();
  } else if (aead_id == HPKE_AEAD_CHACHA20POLY1305) {
    aead = EVP_aead_chacha20_poly1305();
  }
  if (aead == NULL) {
    return 0;
  }

  const uint8_t kZeroPsk[HKDF_SHA256_NH] = {0};
  const uint8_t kZeroSalt[HKDF_SHA256_NH] = {0};

  // pskID_hash = LabeledExtract(zero(Nh), "pskID_hash", pskID)
  static const char kPskIdHashLabel[] = "pskID_hash";
  uint8_t psk_id_hash[EVP_MAX_MD_SIZE];
  size_t psk_id_hash_len;
  if (!hpke_labeled_extract(hpke, psk_id_hash, &psk_id_hash_len, kZeroSalt,
                            sizeof(kZeroSalt), kPskIdHashLabel, NULL, 0)) {
    return 0;
  }

  // info_hash = LabeledExtract(zero(Nh), "info", info)

  // TODO(dmcardle) draft-draft-irtf-cfrg-hpke-04 says "info", but reference
  // implementation uses "info_hash"
  static const char kInfoHashLabel[] = "info_hash";
  uint8_t info_hash[EVP_MAX_MD_SIZE];
  size_t info_hash_len;
  if (!hpke_labeled_extract(hpke, info_hash, &info_hash_len, kZeroSalt,
                            sizeof(kZeroSalt), kInfoHashLabel, info,
                            info_len)) {
    return 0;
  }

  // context = concat(ciphersuite, mode, pskID_hash, info_hash)
  uint8_t context[3 * sizeof(uint16_t) + sizeof(uint8_t) + 2 * EVP_MAX_MD_SIZE];
  CBB context_cbb;
  int ok = (CBB_init_fixed(&context_cbb, context, sizeof(context)) &&
            CBB_add_u16(&context_cbb, EVP_HPKE_DHKEM_X25519_HKDF_SHA256) &&
            CBB_add_u16(&context_cbb, HPKE_HKDF_SHA256) &&
            CBB_add_u16(&context_cbb, aead_id) &&
            CBB_add_u8(&context_cbb, EVP_HPKE_MODE_BASE) &&
            CBB_add_bytes(&context_cbb, psk_id_hash, psk_id_hash_len) &&
            CBB_add_bytes(&context_cbb, info_hash, info_hash_len));

  PrintActual("context", CBB_data(&context_cbb), CBB_len(&context_cbb));

  // psk = LabeledExtract(zero(Nh), "psk_hash", psk)
  //
  // Confusingly, the HPKE draft shadows the `psk` parameter here. For our
  // purposes, that parameter is just the default empty PSK, |kZeroPsk|.
  static const char kPskHashLabel[] = "psk_hash";
  uint8_t psk_hash[EVP_MAX_MD_SIZE];
  size_t psk_hash_len;
  if (!hpke_labeled_extract(hpke, psk_hash, &psk_hash_len, kZeroSalt,
                            sizeof(kZeroSalt), kPskHashLabel, kZeroPsk,
                            sizeof(kZeroPsk))) {
    ok = 0;
  }

  // secret = LabeledExtract(psk, "secret", zz)
  static const char kSecretExtractLabel[] = "secret";
  uint8_t secret[EVP_MAX_MD_SIZE];
  size_t secret_len;
  if (!hpke_labeled_extract(hpke, secret, &secret_len, psk_hash, psk_hash_len,
                            kSecretExtractLabel, zz, zz_len)) {
    ok = 0;
  }

  PrintActual("secret", secret, secret_len);

  // key = LabeledExpand(secret, "key", context, Nk)
  static const char kKeyExpandLabel[] = "key";
  uint8_t key[EVP_AEAD_MAX_KEY_LENGTH];
  size_t key_len = EVP_AEAD_key_length(aead);
  if (!hpke_labeled_expand(hpke, key, key_len, secret, secret_len,
                           kKeyExpandLabel, CBB_data(&context_cbb),
                           CBB_len(&context_cbb))) {
    ok = 0;
  }
  PrintActual("key", key, sizeof(key));

  // Initialize the HPKE context's AEAD context, storing a copy of |key|.
  if (!EVP_AEAD_CTX_init(&hpke->aead_ctx, aead, key, key_len,
                         EVP_AEAD_max_tag_len(aead), NULL)) {
    ok = 0;
  }

  // nonce = LabeledExpand(secret, "nonce", context, Nn)
  static const char kNonceExpandLabel[] = "nonce";
  if (!hpke_labeled_expand(hpke, hpke->nonce, EVP_AEAD_nonce_length(aead),
                           secret, secret_len, kNonceExpandLabel,
                           CBB_data(&context_cbb), CBB_len(&context_cbb))) {
    ok = 0;
  }

  PrintActual("nonce", hpke->nonce, EVP_AEAD_nonce_length(aead));

  // exporter_secret = LabeledExpand(secret, "exp", conetxt, Nh)
  static const char kExporterSecretExpandLabel[] = "exp";
  if (!hpke_labeled_expand(hpke, hpke->exporter_secret, HKDF_SHA256_NH, secret,
                           secret_len, kExporterSecretExpandLabel,
                           CBB_data(&context_cbb), CBB_len(&context_cbb))) {
    ok = 0;
  }

  CBB_cleanup(&context_cbb);
  return ok;
}

static int hpke_increment_seq(EVP_HPKE_CTX *hpke) {
  hpke->seq++;
  return hpke->seq != 0;
}

static void hpke_ephemeral_keypair_set(
    EVP_HPKE_CTX *hpke, const uint8_t private[X25519_PRIVATE_KEY_LEN]) {
  OPENSSL_memcpy(hpke->secret_key_ephemeral, private, X25519_PRIVATE_KEY_LEN);
  hpke->secret_key_ephemeral_len = X25519_PRIVATE_KEY_LEN;
}

static void hpke_ephemeral_keypair_get(EVP_HPKE_CTX *hpke, uint8_t *out_public,
                                       uint8_t *out_private) {
  if (hpke->secret_key_ephemeral_len == 0) {
    X25519_keypair(out_public, out_private);
    // Save a copy of the secret key in |hpke|.
    hpke_ephemeral_keypair_set(hpke, out_private);
    return;
  }

  // Recover the public key from |hpke|.
  X25519_public_from_private(out_public, hpke->secret_key_ephemeral);
  OPENSSL_memcpy(out_private, hpke->secret_key_ephemeral,
                 X25519_PRIVATE_KEY_LEN);
}

static int hpke_encap(EVP_HPKE_CTX *hpke, uint8_t out_zz[SHA256_DIGEST_LENGTH],
                      uint8_t out_enc[X25519_PUBLIC_VALUE_LEN],
                      const uint8_t public_key_r[X25519_PUBLIC_VALUE_LEN]) {
  uint8_t ephemeral_private[X25519_PRIVATE_KEY_LEN];
  hpke_ephemeral_keypair_get(hpke, out_enc, ephemeral_private);

  PrintActual("hpke_encap pkE", out_enc, X25519_PUBLIC_VALUE_LEN);
  PrintActual("hpke_encap skE", ephemeral_private, sizeof(ephemeral_private));

  uint8_t dh[X25519_PUBLIC_VALUE_LEN];
  if (!X25519(dh, ephemeral_private, public_key_r)) {
    return 0;
  }

  uint8_t kem_context[KEM_CONTEXT_LEN];
  OPENSSL_memcpy(kem_context, out_enc, X25519_PUBLIC_VALUE_LEN);
  OPENSSL_memcpy(kem_context + X25519_PUBLIC_VALUE_LEN, public_key_r,
                 X25519_PUBLIC_VALUE_LEN);
  if (!hpke_extract_and_expand(hpke, out_zz, SHA256_DIGEST_LENGTH, dh,
                               kem_context)) {
    return 0;
  }
  return 1;
}

static int hpke_decap(const EVP_HPKE_CTX *hpke,
                      uint8_t out_zz[SHA256_DIGEST_LENGTH],
                      const uint8_t enc[X25519_PUBLIC_VALUE_LEN],
                      const uint8_t secret_key_r[X25519_PRIVATE_KEY_LEN]) {
  uint8_t dh[X25519_PUBLIC_VALUE_LEN];
  if (!X25519(dh, secret_key_r, enc)) {
    return 0;
  }
  uint8_t public_key[X25519_PUBLIC_VALUE_LEN];
  X25519_public_from_private(public_key, secret_key_r);
  uint8_t kem_context[KEM_CONTEXT_LEN];
  OPENSSL_memcpy(kem_context, enc, X25519_PUBLIC_VALUE_LEN);
  OPENSSL_memcpy(kem_context + X25519_PUBLIC_VALUE_LEN, public_key,
                 sizeof(public_key));
  if (!hpke_extract_and_expand(hpke, out_zz, SHA256_DIGEST_LENGTH, dh,
                               kem_context)) {
    return 0;
  }
  return 1;
}

void EVP_HPKE_CTX_init(EVP_HPKE_CTX *ctx) {
  ctx->kem_hkdf_md = EVP_sha256();
  ctx->hkdf_md = EVP_sha256();
  EVP_AEAD_CTX_zero(&ctx->aead_ctx);
  OPENSSL_memset(&ctx->secret_key_ephemeral, 0,
                 sizeof(ctx->secret_key_ephemeral));
  ctx->secret_key_ephemeral_len = 0;
  OPENSSL_memset(&ctx->nonce, 0, sizeof(ctx->nonce));
  OPENSSL_memset(&ctx->exporter_secret, 0, sizeof(ctx->exporter_secret));
  ctx->seq = 0;
}

void EVP_HPKE_CTX_cleanup(EVP_HPKE_CTX *ctx) {
  ctx->kem_hkdf_md = NULL;
  ctx->hkdf_md = NULL;
  EVP_AEAD_CTX_cleanup(&ctx->aead_ctx);
  OPENSSL_memset(ctx->secret_key_ephemeral, 0, ctx->secret_key_ephemeral_len);
  ctx->secret_key_ephemeral_len = 0;
  OPENSSL_memset(ctx->nonce, 0, sizeof(ctx->nonce));
  OPENSSL_memset(ctx->exporter_secret, 0, sizeof(ctx->exporter_secret));
  ctx->seq = 0;
}

int EVP_HPKE_CTX_setup_base_x25519_s(
    EVP_HPKE_CTX *hpke, uint8_t *out_enc, uint16_t aead_id,
    const uint8_t peer_public_value[X25519_PUBLIC_VALUE_LEN],
    const uint8_t *info, size_t info_len) {
  uint8_t zz[SHA256_DIGEST_LENGTH];
  if (!hpke_encap(hpke, zz, out_enc, peer_public_value) ||
      !hpke_key_schedule(hpke, aead_id, zz, sizeof(zz), info, info_len)) {
    return 0;
  }
  return 1;
}

int EVP_HPKE_CTX_setup_base_x25519_r(
    EVP_HPKE_CTX *hpke, uint16_t aead_id,
    const uint8_t enc[X25519_PUBLIC_VALUE_LEN],
    const uint8_t private_key[X25519_PRIVATE_KEY_LEN], const uint8_t *info,
    size_t info_len) {
  uint8_t zz[SHA256_DIGEST_LENGTH];
  if (!hpke_decap(hpke, zz, enc, private_key) ||
      !hpke_key_schedule(hpke, aead_id, zz, sizeof(zz), info, info_len)) {
    return 0;
  }
  return 1;
}

static void hpke_nonce(EVP_HPKE_CTX *hpke, uint8_t *out_nonce,
                       size_t nonce_len) {
  assert(nonce_len >= 8);

  // Write padded big-endian bytes of |hpke->seq| to |out_nonce|.
  OPENSSL_memset(out_nonce, 0, nonce_len);
  uint64_t seq_copy = hpke->seq;
  for (int i = 0; i < sizeof(uint64_t); i++) {
    out_nonce[nonce_len - i - 1] = seq_copy & 0xff;
    seq_copy >>= 8;
  }

  // XOR the encoded sequence with the |hpke->nonce|.
  for (size_t i = 0; i < nonce_len; i++) {
    out_nonce[i] ^= hpke->nonce[i];
  }
}

int EVP_HPKE_CTX_open(EVP_HPKE_CTX *hpke, uint8_t *out, size_t *out_len,
                      size_t max_out_len, const uint8_t *in, size_t in_len,
                      const uint8_t *ad, size_t ad_len) {
  uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH];
  const size_t nonce_len = EVP_AEAD_nonce_length(hpke->aead_ctx.aead);
  hpke_nonce(hpke, nonce, nonce_len);

  if (!EVP_AEAD_CTX_open(&hpke->aead_ctx, out, out_len, max_out_len, nonce,
                         nonce_len, in, in_len, ad, ad_len) ||
      !hpke_increment_seq(hpke)) {
    return 0;
  }
  return 1;
}

int EVP_HPKE_CTX_seal(EVP_HPKE_CTX *hpke, uint8_t *out, size_t *out_len,
                      size_t max_out_len, const uint8_t *in, size_t in_len,
                      const uint8_t *ad, size_t ad_len) {
  uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH];
  const size_t nonce_len = EVP_AEAD_nonce_length(hpke->aead_ctx.aead);
  hpke_nonce(hpke, nonce, nonce_len);

  if (!EVP_AEAD_CTX_seal(&hpke->aead_ctx, out, out_len, max_out_len, nonce,
                         EVP_AEAD_nonce_length(hpke->aead_ctx.aead), in, in_len,
                         ad, ad_len) ||
      !hpke_increment_seq(hpke)) {
    return 0;
  }
  return 1;
}

int EVP_HPKE_CTX_export(EVP_HPKE_CTX *hpke, uint8_t *secret_out,
                        size_t secret_len, const uint8_t *context,
                        size_t context_len) {
  static const char kExportExpandLabel[] = "sec";
  if (!hpke_labeled_expand(hpke, secret_out, secret_len, hpke->exporter_secret,
                           SHA256_DIGEST_LENGTH, kExportExpandLabel, context,
                           context_len)) {
    return 0;
  }
  return 1;
}
