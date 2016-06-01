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

  size_t i;
  printf("PRK (%zu): ", secret_len);
  for (i = 0; i < secret_len; i++) {
    printf("%02x", secret[i]);
  }
  printf("\n");
  printf("LABEL (%zu): ", CBB_len(&cbb));
  for (i = 0; i < CBB_len(&cbb); i++) {
    printf("%02x", CBB_data(&cbb)[i]);
  }
  printf("\n");
  printf("HASH (%zu): ", hash_len);
  for (i = 0; i < hash_len; i++) {
    printf("%02x", hash[i]);
  }
  printf("\n");


  return HKDF_expand(out, len, digest, secret, secret_len, CBB_data(&cbb),
                     CBB_len(&cbb));
}

static int derive_secret(SSL *ssl, uint8_t *out, size_t len,
                         uint8_t *secret, size_t secret_len,
                         const uint8_t *label, size_t label_len) {
  SSL_HANDSHAKE *hs = ssl->s3->hs;
  const EVP_MD *digest = ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl));

  size_t i;
  printf("DS:\n");
  printf("\tMSG: ");
  for (i = 0; i < label_len; i++) {
    printf("%02x", label[i]);
  }
  printf("\n");
  printf("\tSECRET: ");
  for (i = 0; i < secret_len; i++) {
    printf("%02x", secret[i]);
  }
  printf("\n");
  printf("\tHASH: ");
  for (i = 0; i < hs->hash_context_len; i++) {
    printf("%02x", hs->hash_context[i]);
  }
  printf("\n");



  return hkdf_expand_label(out, digest, secret, secret_len, label, label_len,
                           hs->hash_context, hs->hash_context_len, len);
}

const uint8_t kTLS13LabelServerKey[16] = "server write key";
const uint8_t kTLS13LabelServerIV[15] = "server write iv";
const uint8_t kTLS13LabelClientKey[16] = "client write key";
const uint8_t kTLS13LabelClientIV[15] = "client write iv";

static int set_traffic_key(SSL *ssl, enum tls_record_type_t type,
                           enum evp_aead_direction_t direction) {
  uint8_t *secret = NULL;
  size_t secret_len = ssl->s3->traffic_secret_len;
  if (direction == evp_aead_open) {
    secret = ssl->s3->open_traffic_secret;
  } else {
    secret = ssl->s3->seal_traffic_secret;
  }

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

  uint8_t *key = OPENSSL_malloc(key_len);
  uint8_t *iv = OPENSSL_malloc(iv_len);

  uint8_t *type_label;
  size_t type_label_len;
  switch(type) {
    case type_early_handshake:
      type_label = (uint8_t *)"early handshake key expansion, ";
      type_label_len = 31;
      break;
    case type_early_data:
      type_label = (uint8_t *)"early application data key expansion, ";
      type_label_len = 38;
      break;
    case type_handshake:
      type_label = (uint8_t *)"handshake key expansion, ";
      type_label_len = 25;
      break;
    case type_data:
      type_label = (uint8_t *)"application data key expansion, ";
      type_label_len = 32;
      break;
  }

  CBB key_label, iv_label;
  if (!CBB_init(&key_label, type_label_len + 16) ||
      !CBB_add_bytes(&key_label, type_label, type_label_len) ||
      !CBB_init(&iv_label, type_label_len + 15) ||
      !CBB_add_bytes(&iv_label, type_label, type_label_len)) {
    return 0;
  }

  if ((ssl->server && direction == evp_aead_seal) ||
      (!ssl->server && direction == evp_aead_open)) {
    if (!CBB_add_bytes(&key_label,
                       kTLS13LabelServerKey, sizeof(kTLS13LabelServerKey)) ||
        !CBB_add_bytes(&iv_label,
                       kTLS13LabelServerIV, sizeof(kTLS13LabelServerIV))) {
      return 0;
    }
  } else {
    if (!CBB_add_bytes(&key_label,
                       kTLS13LabelClientKey, sizeof(kTLS13LabelClientKey)) ||
        !CBB_add_bytes(&iv_label,
                       kTLS13LabelClientIV, sizeof(kTLS13LabelClientIV))) {
      return 0;
    }
  }

  if (!hkdf_expand_label(key, digest, secret, secret_len,
                         CBB_data(&key_label), CBB_len(&key_label), NULL, 0,
                         key_len) ||
      !hkdf_expand_label(iv, digest, secret, secret_len,
                         CBB_data(&iv_label), CBB_len(&iv_label), NULL, 0,
                         iv_len)) {
    return 0;
  }

  SSL_AEAD_CTX *traffic_aead = SSL_AEAD_CTX_new(direction,
                                                ssl3_protocol_version(ssl),
                                                ssl->session->cipher,
                                                key, key_len, NULL, 0,
                                                iv, iv_len);
  if (traffic_aead == NULL) {
    return 0;
  }
  size_t i;

  if (direction == evp_aead_open) {
    printf("R_K: ");
  } else {
    printf("W_K: ");
  }
  for (i = 0; i < key_len; i++) {
    printf("%02x", key[i]);
  }
  printf("\n");
  if (direction == evp_aead_open) {
    printf("R_I: ");
  } else {
    printf("W_I: ");
  }
  for (i = 0; i < iv_len; i++) {
    printf("%02x", iv[i]);
  }
  printf("\n");

  if (direction == evp_aead_open) {
    ssl_set_read_state(ssl, traffic_aead);
  } else {
    ssl_set_write_state(ssl, traffic_aead);
  }

  return 1;
}

const uint8_t kTLS13LabelEarlyTraffic[20] = "early traffic secret";
const uint8_t kTLS13LabelHandshakeTraffic[24] = "handshake traffic secret";
const uint8_t kTLS13LabelApplicationTraffic[26] = "application traffic secret";

int tls13_update_traffic_secret(SSL *ssl, enum tls_record_type_t type) {
  SSL_HANDSHAKE *hs = ssl->s3->hs;

  if (!ssl->s3->traffic_secret_len) {
    ssl->s3->traffic_secret_len = hs->key_len;
    ssl->s3->open_traffic_secret = OPENSSL_malloc(ssl->s3->traffic_secret_len);
    ssl->s3->seal_traffic_secret = OPENSSL_malloc(ssl->s3->traffic_secret_len);
  }

  const uint8_t *label;
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
      break;
    case type_handshake:
      label = kTLS13LabelHandshakeTraffic;
      label_len = sizeof(kTLS13LabelHandshakeTraffic);
      secret = hs->handshake_secret;
      secret_len = hs->handshake_secret_len;
      break;
    case type_data:
      label = kTLS13LabelApplicationTraffic;
      label_len = sizeof(kTLS13LabelApplicationTraffic);
      secret = hs->master_secret;
      secret_len = hs->master_secret_len;
      break;
  }

  size_t i;
  printf("SECRET (%zu): ", secret_len);
  for (i = 0; i < secret_len; i++) {
    printf("%02x", secret[i]);
  }
  printf("\n");

  if (!derive_secret(ssl, ssl->s3->open_traffic_secret,
                     ssl->s3->traffic_secret_len,
                     secret, secret_len, label, label_len) ||
      !set_traffic_key(ssl, type, evp_aead_open) ||
      !derive_secret(ssl, ssl->s3->seal_traffic_secret,
                     ssl->s3->traffic_secret_len,
                     secret, secret_len, label, label_len) ||
      !set_traffic_key(ssl, type, evp_aead_seal)) {
    return 0;
  }
  return 1;
}

int tls13_derive_secrets(SSL *ssl) {
  SSL_HANDSHAKE *hs = ssl->s3->hs;
  const EVP_MD *digest = ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl));

  if (hs->psk_secret == NULL) {
    hs->psk_secret_len = hs->key_len;
    hs->psk_secret = OPENSSL_malloc(hs->psk_secret_len);
    memset(hs->psk_secret, 0, hs->psk_secret_len);
  }

  if (hs->dhe_secret == NULL) {
    hs->dhe_secret_len = hs->key_len;
    hs->dhe_secret = OPENSSL_malloc(hs->dhe_secret_len);
    memset(hs->dhe_secret, 0, hs->dhe_secret_len);
  }

  if (hs->early_secret != NULL) {
    OPENSSL_free(hs->early_secret);
  }
  hs->early_secret = OPENSSL_malloc(hs->key_len);
  if (!HKDF_extract(hs->early_secret, &hs->early_secret_len,
                    digest, hs->psk_secret, hs->psk_secret_len, NULL, 0)) {
    return 0;
  }

  if (hs->handshake_secret != NULL) {
    OPENSSL_free(hs->handshake_secret);
  }
  hs->handshake_secret = OPENSSL_malloc(hs->key_len);
  if (!HKDF_extract(hs->handshake_secret, &hs->handshake_secret_len,
                    digest, hs->dhe_secret, hs->dhe_secret_len,
                    hs->early_secret, hs->early_secret_len)) {
    return 0;
  }

  uint8_t *zero = OPENSSL_malloc(hs->key_len);
  memset(zero, 0, hs->key_len);

  if (hs->master_secret != NULL) {
    OPENSSL_free(hs->master_secret);
  }
  hs->master_secret = OPENSSL_malloc(hs->key_len);
  if (!HKDF_extract(hs->master_secret, &hs->master_secret_len,
                    digest, zero, hs->key_len,
                    hs->handshake_secret, hs->handshake_secret_len)) {
    return 0;
  }

  size_t i;
  printf("MS: ");
  for(i = 0; i < hs->master_secret_len; i++) {
    printf("%02x", hs->master_secret[i]);
  }
  printf("\n");

  return 1;
}

int tls13_derive_traffic_secret_0(SSL *ssl) {
  SSL_HANDSHAKE *hs = ssl->s3->hs;

  if (hs->traffic_secret_0 == NULL) {
    hs->traffic_secret_0 = OPENSSL_malloc(hs->key_len);
  }

  return derive_secret(ssl, hs->traffic_secret_0, hs->key_len,
                       hs->master_secret, hs->master_secret_len,
                       kTLS13LabelApplicationTraffic,
                       sizeof(kTLS13LabelApplicationTraffic));
}

const uint8_t kTLS13LabelExporter[22] = "exporter master secret";
const uint8_t kTLS13LabelResumption[24] = "resumption master secret";

int tls13_finalize_keys(SSL *ssl) {
  SSL_HANDSHAKE *hs = ssl->s3->hs;

  memcpy(ssl->s3->open_traffic_secret, hs->traffic_secret_0,
         ssl->s3->traffic_secret_len);
  memcpy(ssl->s3->seal_traffic_secret, hs->traffic_secret_0,
         ssl->s3->traffic_secret_len);
  if (!set_traffic_key(ssl, type_data, evp_aead_open) ||
      !set_traffic_key(ssl, type_data, evp_aead_seal)) {
    return 0;
  }

  ssl->s3->exporter_secret_len = hs->key_len;
  ssl->s3->resumption_secret_len = hs->key_len;

  if (ssl->s3->exporter_secret == NULL) {
    ssl->s3->exporter_secret = OPENSSL_malloc(hs->key_len);
    ssl->s3->exporter_secret_len = hs->key_len;
  }

  if (ssl->s3->resumption_secret == NULL) {
    ssl->s3->resumption_secret = OPENSSL_malloc(hs->key_len);
    ssl->s3->resumption_secret_len = hs->key_len;
  }

  if (!tls13_store_handshake_context(ssl)) {
    return 0;
  }

  if (!derive_secret(ssl,
                     ssl->s3->exporter_secret, ssl->s3->exporter_secret_len,
                     hs->master_secret, hs->master_secret_len,
                     kTLS13LabelExporter, sizeof(kTLS13LabelExporter)) ||
      !derive_secret(ssl,
                     ssl->s3->resumption_secret, ssl->s3->resumption_secret_len,
                     hs->master_secret, hs->master_secret_len,
                     kTLS13LabelResumption, sizeof(kTLS13LabelResumption))) {
    return 0;
  }

  memcpy(ssl->session->master_key, ssl->s3->resumption_secret,
         ssl->s3->resumption_secret_len);
  ssl->session->master_key_length = ssl->s3->resumption_secret_len;

  OPENSSL_cleanse(hs->early_secret, hs->early_secret_len);
  OPENSSL_free(hs->early_secret);
  OPENSSL_cleanse(hs->handshake_secret, hs->handshake_secret_len);
  OPENSSL_free(hs->handshake_secret);
  OPENSSL_cleanse(hs->master_secret, hs->master_secret_len);
  OPENSSL_free(hs->master_secret);

  return 1;
}

int tls13_rotate_traffic_secret(SSL *ssl, enum evp_aead_direction_t direction) {
  const EVP_MD *digest = ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl));

  if (direction == evp_aead_open) {
    if (!hkdf_expand_label(ssl->s3->open_traffic_secret, digest,
                           ssl->s3->open_traffic_secret,
                           ssl->s3->traffic_secret_len,
                           kTLS13LabelApplicationTraffic,
                           sizeof(kTLS13LabelApplicationTraffic),
                           NULL, 0, ssl->s3->traffic_secret_len)) {
      return 0;
    }
  } else {
    if (!hkdf_expand_label(ssl->s3->seal_traffic_secret, digest,
                           ssl->s3->seal_traffic_secret,
                           ssl->s3->traffic_secret_len,
                           kTLS13LabelApplicationTraffic,
                           sizeof(kTLS13LabelApplicationTraffic),
                           NULL, 0, ssl->s3->traffic_secret_len)) {
      return 0;
    }
  }
  return set_traffic_key(ssl, type_data, direction);
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
                           ssl->s3->exporter_secret, ssl->s3->exporter_secret_len,
                           (const uint8_t *)label, label_len, hash, hash_len, out_len);
}

const uint8_t kTLS13LabelClientFinished[24] = "TLS 1.3, client finished";
const uint8_t kTLS13LabelServerFinished[24] = "TLS 1.3, server finished";
const uint8_t kTLS13LabelTraffic[23] = "TLS 1.3, traffic secret";

int tls13_verify_finished(SSL *ssl, uint8_t *out, size_t *out_len,
                          char is_server) {
  SSL_HANDSHAKE *hs = ssl->s3->hs;
  const EVP_MD *digest = ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl));

  uint8_t *key = OPENSSL_malloc(EVP_MAX_MD_SIZE);
  size_t key_len = EVP_MD_size(digest);

  if (key == NULL) {
    return 0;
  }

  uint8_t *traffic_secret;
  const uint8_t *label;
  if (is_server) {
    label = (uint8_t *)"server finished";
    if (ssl->server) {
      traffic_secret = ssl->s3->seal_traffic_secret;
    } else {
      traffic_secret = ssl->s3->open_traffic_secret;
    }
  } else {
    label = (uint8_t *)"client finished";
    if (!ssl->server) {
      traffic_secret = ssl->s3->seal_traffic_secret;
    } else {
      traffic_secret = ssl->s3->open_traffic_secret;
    }
  }
  size_t label_len = 15;



  if (!hkdf_expand_label(key, digest, traffic_secret, hs->key_len,
                         label, label_len, NULL, 0, hs->key_len)) {
    return 0;
  }

  unsigned len;
  if (HMAC(digest, key, key_len, hs->hash_context, hs->hash_context_len,
           out, &len) == NULL) {
    return 0;
  }
  *out_len = len;

  size_t i;
  printf("HASH+RESUMPTION: ");
  for (i = 0; i < hs->hash_context_len; i++) {
    printf("%02x", hs->hash_context[i]);
  }
  printf("\n");

  printf("BKEY: ");
  for (i = 0; i < hs->key_len; i++) {
    printf("%02x", traffic_secret[i]);
  }
  printf("\n");

  printf("FINISHED: ");
  for (i = 0; i < *out_len; i++) {
    printf("%02x", out[i]);
  }
  printf("\n");

  OPENSSL_free(key);
  return 1;
}

int tls13_cert_verify_digest(SSL *ssl, uint8_t *digest, size_t *digest_len, char server,
                             const EVP_MD *md) {
  int ret = 0;
  EVP_MD_CTX mctx;
  CBB hashed_data;

  if (!CBB_init(&hashed_data, 98 + ssl->s3->hs->hash_context_len)) {
    goto err;
  }

  size_t pad;
  for (pad = 0; pad < 64; pad++) {
    if (!CBB_add_u8(&hashed_data, 0x20)) {
      goto err;
    }
  }

  if (server) {
    const uint8_t kContext[] = "TLS 1.3, server CertificateVerify";

    if (!CBB_add_bytes(&hashed_data, kContext, sizeof(kContext))) {
      goto err;
    }
  } else {
    const uint8_t kContext[] = "TLS 1.3, client CertificateVerify";

    if (!CBB_add_bytes(&hashed_data, kContext, sizeof(kContext))) {
      goto err;
    }
  }

  if (!CBB_add_bytes(&hashed_data, ssl->s3->hs->hash_context,
                     ssl->s3->hs->hash_context_len)) {
    goto err;
  }

  unsigned len;
  EVP_MD_CTX_init(&mctx);
  if (!EVP_DigestInit_ex(&mctx, md, NULL) ||
      !EVP_DigestUpdate(&mctx, CBB_data(&hashed_data), CBB_len(&hashed_data)) ||
      !EVP_DigestFinal(&mctx, digest, &len)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_EVP_LIB);
    goto err;
  }
  *digest_len = len;

  ret = 1;

err:
  EVP_MD_CTX_cleanup(&mctx);
  CBB_cleanup(&hashed_data);
  return ret;
}
