/* Copyright (c) 2016, Google Inc.
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

#include <string.h>

#include <openssl/hkdf.h>
#include <openssl/ssl.h>

#include "internal.h"

const uint8_t kTLS13LabelVersion[9] = "TLS 1.3, ";

static int hkdf_expand_label(uint8_t *out, const EVP_MD *digest,
                             uint8_t *secret, size_t secret_len,
                             const uint8_t *label, size_t label_len,
                             const uint8_t *hash, size_t hash_len,
                             size_t len) {
  CBB hkdf_label;
  CBB cbb;
  if (!CBB_init(&cbb, 2 + 1 + label_len + 1 + hash_len) ||
      !CBB_add_u16(&cbb, len) ||
      !CBB_add_u8_length_prefixed(&cbb, &hkdf_label) ||
      !CBB_add_bytes(&hkdf_label, kTLS13LabelVersion,
                     sizeof(kTLS13LabelVersion)) ||
      !CBB_add_bytes(&hkdf_label, label, label_len) ||
      !CBB_add_u8(&cbb, hash_len) ||
      !CBB_add_bytes(&cbb, hash, hash_len)) {
    return 0;
  }

  return HKDF_expand(out, len, digest, secret, secret_len, CBB_data(&cbb),
                     CBB_len(&cbb));
}

static int derive_secret(SSL *ssl, uint8_t *out, size_t len,
                         uint8_t *secret, size_t secret_len,
                         uint8_t *label, size_t label_len) {
  SSL_HANDSHAKE *hs = ssl->s3->hs;
  const EVP_MD *digest = ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl));

  CBB msg;
  if (!CBB_init(&msg, hs->hs_context_len + hs->resumption_ctx_len) ||
      !CBB_add_bytes(&msg, hs->hs_context, hs->hs_context_len) ||
      !CBB_add_bytes(&msg, hs->resumption_ctx, hs->resumption_ctx_len)) {
   return 0;
  }
  return hkdf_expand_label(out, digest, secret, secret_len, label, label_len,
                           CBB_data(&msg), CBB_len(&msg), len);
}

const uint8_t kTLS13LabelServerKey[16] = "server write key";
const uint8_t kTLS13LabelServerIV[15] = "server write iv";
const uint8_t kTLS13LabelClientKey[16] = "client write key";
const uint8_t kTLS13LabelClientIV[15] = "client write iv";

static int set_traffic_key(SSL *ssl, enum tls_record_type_t type) {
  uint8_t *secret = ssl->s3->traffic_secret;
  size_t secret_len = ssl->s3->traffic_secret_len;

  const EVP_AEAD *aead;
  const EVP_MD *digest = ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl));
  size_t mac_secret_len, fixed_iv_len;
  if (!ssl_cipher_get_evp_aead(&aead, &mac_secret_len, &fixed_iv_len,
                               ssl->session->cipher,
                               ssl3_protocol_version(ssl))) {
    return 0;
  }
  size_t key_len = EVP_AEAD_key_length(aead);
  size_t iv_len = EVP_AEAD_nonce_length(aead);

  uint8_t *write_key = OPENSSL_malloc(key_len);
  uint8_t *write_iv = OPENSSL_malloc(iv_len);
  uint8_t *read_key = OPENSSL_malloc(key_len);
  uint8_t *read_iv = OPENSSL_malloc(iv_len);

  uint8_t *type_label;
  size_t type_label_len;
  switch(type) {
    case type_early_handshake:
      type_label = (uint8_t *)"early handshake key expansion, ";
      type_label_len = 15;
    case type_early_data:
      type_label = (uint8_t *)"early application data key expansion, ";
      type_label_len = 22;
    case type_handshake:
      type_label = (uint8_t *)"handshake key expansion, ";
      type_label_len = 9;
    case type_data:
      type_label = (uint8_t *)"application data key expansion, ";
      type_label_len = 16;
  }

  CBB ck_label, ci_label, sk_label, si_label;

  if (!CBB_init(&ck_label, type_label_len + 16) ||
      !CBB_add_bytes(&ck_label, type_label, type_label_len) ||
      !CBB_add_bytes(&ck_label, kTLS13LabelClientKey,
                     sizeof(kTLS13LabelClientKey)) ||
      !CBB_init(&ci_label, type_label_len + 15) ||
      !CBB_add_bytes(&ci_label, type_label, type_label_len) ||
      !CBB_add_bytes(&ci_label, kTLS13LabelClientIV,
                     sizeof(kTLS13LabelClientKey)) ||
      !CBB_init(&sk_label, type_label_len + 16) ||
      !CBB_add_bytes(&sk_label, type_label, type_label_len) ||
      !CBB_add_bytes(&sk_label, kTLS13LabelServerKey,
                     sizeof(kTLS13LabelClientKey)) ||
      !CBB_init(&si_label, type_label_len + 15) ||
      !CBB_add_bytes(&si_label, type_label, type_label_len) ||
      !CBB_add_bytes(&si_label, kTLS13LabelServerIV,
                     sizeof(kTLS13LabelClientKey))) {
    return 0;
  }

  CBB wk_label, wi_label, rk_label, ri_label;

  if (ssl->server) {
    wk_label = sk_label;
    wi_label = si_label;
    rk_label = ck_label;
    ri_label = ci_label;
  } else {
    wk_label = ck_label;
    wi_label = ci_label;
    rk_label = sk_label;
    ri_label = si_label;
  }

  if (!hkdf_expand_label(write_key, digest, secret, secret_len,
                         CBB_data(&wk_label), CBB_len(&wk_label), NULL, 0,
                         key_len) ||
      !hkdf_expand_label(write_iv, digest, secret, secret_len,
                         CBB_data(&wi_label), CBB_len(&wi_label), NULL, 0,
                         iv_len) ||
      !hkdf_expand_label(read_key, digest, secret, secret_len,
                         CBB_data(&rk_label), CBB_len(&rk_label), NULL, 0,
                         key_len) ||
      !hkdf_expand_label(read_iv, digest, secret, secret_len,
                         CBB_data(&ri_label), CBB_len(&ri_label), NULL, 0,
                         iv_len)) {
    return 0;
  }

  SSL_AEAD_CTX *read_aead = SSL_AEAD_CTX_new(
      evp_aead_open, ssl3_protocol_version(ssl), ssl->session->cipher,
      read_key, key_len, NULL, 0, read_iv, iv_len);
  SSL_AEAD_CTX *write_aead = SSL_AEAD_CTX_new(
      evp_aead_seal, ssl3_protocol_version(ssl), ssl->session->cipher,
      write_key, key_len, NULL, 0, write_iv, iv_len);
  if (read_aead == NULL || write_aead == NULL) {
    return 0;
  }

  ssl_set_read_state(ssl, read_aead);
  ssl_set_write_state(ssl, write_aead);
  return 1;
}

const uint8_t kTLS13LabelEarlyTraffic[20] = "early traffic secret";
const uint8_t kTLS13LabelHandshakeTraffic[24] = "handshake traffic secret";
const uint8_t kTLS13LabelApplicationTraffic[26] = "application traffic secret";

int tls13_update_traffic_secret(SSL *ssl, enum tls_record_type_t type) {
  SSL_HANDSHAKE *hs = ssl->s3->hs;

  if (ssl->s3->traffic_secret == NULL) {
    ssl->s3->traffic_secret_len = hs->key_len;
    ssl->s3->traffic_secret = OPENSSL_malloc(ssl->s3->traffic_secret_len);
  }

  uint8_t *label;
  size_t label_len;
  uint8_t *secret;
  size_t secret_len;
  switch (type) {
    case type_early_handshake:
    case type_early_data:
      label = kTLS13LabelEarlyTraffic;
      label_len = sizeof(kTLS13LabelEarlyTraffic);
      secret = hs->early_secret;
      secret_len = hs->early_secret_len;
    case type_handshake:
      label = kTLS13LabelHandshakeTraffic;
      label_len = sizeof(kTLS13LabelHandshakeTraffic);
      secret = hs->handshake_secret;
      secret_len = hs->handshake_secret_len;
    case type_data:
      label = kTLS13LabelApplicationTraffic;
      label_len = sizeof(kTLS13LabelApplicationTraffic);
      secret = hs->master_secret;
      secret_len = hs->master_secret_len;
  }

  if (!derive_secret(ssl, ssl->s3->traffic_secret, ssl->s3->traffic_secret_len,
                     secret, secret_len, label, label_len)) {
    return 0;
  }
  return set_traffic_key(ssl, type);
}

const uint8_t kTLS13LabelExporter[22] = "exporter master secret";
const uint8_t kTLS13LabelResumption[24] = "resumption master secret";

int tls13_finalize_keys(SSL *ssl) {
  SSL_HANDSHAKE *hs = ssl->s3->hs;
  const EVP_MD *digest = ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl));

  if (hs->master_secret == NULL) {
    hs->master_secret = OPENSSL_malloc(EVP_MAX_MD_SIZE);
  }

  if (!HKDF_extract(hs->master_secret, &hs->master_secret_len,
                    digest, NULL, 0,
                    hs->handshake_secret, hs->handshake_secret_len)) {
    return 0;
  }
  if (!tls13_update_traffic_secret(ssl, type_data)) {
    return 0;
  }

  ssl->s3->exporter_secret_len = hs->key_len;
  ssl->s3->resumption_secret_len = hs->key_len;

  if (!derive_secret(ssl,
                     &ssl->s3->exporter_secret, ssl->s3->exporter_secret_len,
                     hs->master_secret, hs->master_secret_len,
                     kTLS13LabelExporter, sizeof(kTLS13LabelExporter)) ||
      !derive_secret(ssl,
                     &ssl->s3->resumption_secret, ssl->s3->resumption_secret_len,
                     hs->master_secret, hs->master_secret_len,
                     kTLS13LabelResumption, sizeof(kTLS13LabelResumption))) {
    return 0;
  }

  OPENSSL_cleanse(hs->early_secret, hs->early_secret_len);
  OPENSSL_free(hs->early_secret);
  OPENSSL_cleanse(hs->handshake_secret, hs->handshake_secret_len);
  OPENSSL_free(hs->handshake_secret);
  OPENSSL_cleanse(hs->master_secret, hs->master_secret_len);
  OPENSSL_free(hs->master_secret);

  return 1;
}

int tls13_rotate_traffic_secret(SSL *ssl) {
  const EVP_MD *digest = ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl));

  if (!hkdf_expand_label(ssl->s3->traffic_secret, digest,
                         ssl->s3->traffic_secret, ssl->s3->traffic_secret_len,
                         kTLS13LabelApplicationTraffic,
                         sizeof(kTLS13LabelApplicationTraffic),
                         NULL, 0, ssl->s3->traffic_secret_len)) {
    return 0;
  }
  return set_traffic_key(ssl, type_data);
}

int tls13_export_keying_material(SSL *ssl, uint8_t *out, size_t out_len,
                                 const char *label, size_t label_len,
                                 const uint8_t *context, size_t context_len,
                                 int use_context) {
  const EVP_MD *digest = ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl));

  const uint8_t *hash = NULL;
  size_t hash_len = 0;
  if (use_context) {
    hash = context;
    hash_len = context_len;
  }
  return hkdf_expand_label(out, digest,
                           ssl->s3->exporter_secret, ssl->s3->export_secret_len,
                           label, label_len, hash, hash_len, out_len);
}
