#include <string.h>

#include <openssl/hkdf.h>
#include <openssl/ssl.h>

#include "internal.h"

const uint8_t kTLS13LabelVersion[9] = "TLS 1.3, ";
const uint8_t kTLS13LabelPhase[16] = " key expansion, ";

const uint8_t kTLS13LabelHandshake[9] = "handshake";
const uint8_t kTLS13LabelData[16] = "application data";
const uint8_t kTLS13LabelEarlyHandshake[15] = "early handshake";
const uint8_t kTLS13LabelEarlyData[22] = "early application data";

const uint8_t kTLS13LabelServerKey[16] = "server write key";
const uint8_t kTLS13LabelServerIV[15] = "server write iv";
const uint8_t kTLS13LabelClientKey[16] = "client write key";
const uint8_t kTLS13LabelClientIV[15] = "client write iv";

const uint8_t kTLS13LabelmSS[31] = "TLS 1.3, expanded static secret";
const uint8_t kTLS13LabelmES[34] = "TLS 1.3, expanded ephemeral secret";

const uint8_t kTLS13LabelClientFinished[24] = "TLS 1.3, client finished";
const uint8_t kTLS13LabelServerFinished[24] = "TLS 1.3, server finished";
const uint8_t kTLS13LabelTraffic[23] = "TLS 1.3, traffic secret";

enum tls13_record_key_t {
  tls13_record_server_key,
  tls13_record_server_iv,
  tls13_record_client_key,
  tls13_record_client_iv,
};

static int tls13_label(const uint8_t **out, size_t *out_len,
                       const uint8_t *label, size_t label_len,
                       uint8_t *hash, size_t hash_len,
                       size_t hkdf_len) {
  CBB cbb;
  if (!CBB_init(&cbb, 2 + 1 + label_len + 1 + hash_len) ||
      !CBB_add_u16(&cbb, hkdf_len) ||
      !CBB_add_u8(&cbb, label_len) ||
      !CBB_add_bytes(&cbb, label, label_len) ||
      !CBB_add_u8(&cbb, hash_len) ||
      !CBB_add_bytes(&cbb, hash, hash_len)) {
    return 0;
  }

  *out = CBB_data(&cbb);
  *out_len = CBB_len(&cbb);
  return 1;
}

static int tls13_traffic_label(const uint8_t **out, size_t *out_len,
                               TLS13_RECORD_TYPE type,
                               enum tls13_record_key_t source,
                               size_t hkdf_len, uint8_t *hash, size_t hash_len) {
  CBB label;

  if (!CBB_init(&label, 60) ||
      !CBB_add_bytes(&label, kTLS13LabelVersion, sizeof(kTLS13LabelVersion))) {
    return 0;
  }

  switch (type) {
    case tls13_type_handshake:
      if (!CBB_add_bytes(&label, kTLS13LabelHandshake, sizeof(kTLS13LabelHandshake))) {
        return 0;
      }
      break;
    case tls13_type_data:
      if (!CBB_add_bytes(&label, kTLS13LabelData, sizeof(kTLS13LabelData))) {
        return 0;
      }
      break;
    case tls13_type_early_handshake:
      if (!CBB_add_bytes(&label, kTLS13LabelEarlyHandshake,
                         sizeof(kTLS13LabelEarlyHandshake))) {
        return 0;
      }
      break;
    case tls13_type_early_data:
      if (!CBB_add_bytes(&label, kTLS13LabelEarlyData, sizeof(kTLS13LabelEarlyData))) {
        return 0;
      }
      break;
  }

  if (!CBB_add_bytes(&label, kTLS13LabelPhase, sizeof(kTLS13LabelPhase))) {
    return 0;
  }

  switch (source) {
    case tls13_record_server_key:
      if (!CBB_add_bytes(&label, kTLS13LabelServerKey,
                         sizeof(kTLS13LabelServerKey))) {
        return 0;
      }
      break;
    case tls13_record_server_iv:
      if (!CBB_add_bytes(&label, kTLS13LabelServerIV,
                         sizeof(kTLS13LabelServerIV))) {
        return 0;
      }
      break;
    case tls13_record_client_key:
      if (!CBB_add_bytes(&label, kTLS13LabelClientKey,
                         sizeof(kTLS13LabelClientKey))) {
        return 0;
      }
      break;
    case tls13_record_client_iv:
      if (!CBB_add_bytes(&label, kTLS13LabelClientIV,
                         sizeof(kTLS13LabelClientIV))) {
        return 0;
      }
      break;
  }

  return tls13_label(out, out_len, CBB_data(&label), CBB_len(&label),
                     hash, hash_len, hkdf_len);
}

int tls13_update_traffic_keys(SSL *ssl, TLS13_RECORD_TYPE key_type,
                              uint8_t *secret, size_t secret_len,
                              uint8_t *hash, size_t hash_len) {
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

  const uint8_t *client_key_label;
  size_t client_key_label_len;
  const uint8_t *client_iv_label;
  size_t client_iv_label_len;
  const uint8_t *server_key_label;
  size_t server_key_label_len;
  const uint8_t *server_iv_label;
  size_t server_iv_label_len;
  if (!tls13_traffic_label(&client_key_label, &client_key_label_len, key_type,
                           tls13_record_client_key, key_len, hash, hash_len) ||
      !tls13_traffic_label(&client_iv_label, &client_iv_label_len, key_type,
                           tls13_record_client_iv, iv_len, hash, hash_len) ||
      !tls13_traffic_label(&server_key_label, &server_key_label_len, key_type,
                           tls13_record_server_key, key_len, hash, hash_len) ||
      !tls13_traffic_label(&server_iv_label, &server_iv_label_len, key_type,
                           tls13_record_server_iv, iv_len, hash, hash_len)) {
    return 0;
  }


  if (!HKDF_expand(write_key, key_len, digest, secret, secret_len,
            client_key_label, client_key_label_len) ||
      !HKDF_expand(write_iv, iv_len, digest, secret, secret_len,
            client_iv_label, client_iv_label_len) ||
      !HKDF_expand(read_key, key_len, digest, secret, secret_len,
            server_key_label, server_key_label_len) ||
      !HKDF_expand(read_iv, iv_len, digest, secret, secret_len,
            server_iv_label, server_iv_label_len)) {
    return 0;
  }

  size_t i;
  printf("SECRET: ");
  for (i = 0; i < secret_len; i++) {
    printf("%02x", secret[i]);
  }
  printf("\n");
  printf("HASH: ");
  for (i = 0; i < hash_len; i++) {
    printf("%02x", hash[i]);
  }
  printf("\n");
  printf("R_K: ");
  for (i = 0; i < key_len; i++) {
    printf("%02x", read_key[i]);
  }
  printf("\n");
  printf("W_I: ");
  for (i = 0; i < iv_len; i++) {
    printf("%02x", read_iv[i]);
  }
  printf("\n");
  printf("W_K: ");
  for (i = 0; i < key_len; i++) {
    printf("%02x", write_key[i]);
  }
  printf("\n");
  printf("W_I: ");
  for (i = 0; i < iv_len; i++) {
    printf("%02x", write_iv[i]);
  }
  printf("\n");

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

int tls13_update_master_secret(SSL *ssl) {
  const EVP_MD *digest = ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl));
  uint8_t *mSS = OPENSSL_malloc(EVP_MAX_MD_SIZE);
  uint8_t *mES = OPENSSL_malloc(EVP_MAX_MD_SIZE);

  EVP_MD_CTX hh;
  EVP_MD_CTX_init(&hh);
  if (!EVP_MD_CTX_copy_ex(&hh, &ssl->s3->handshake_hash)) {
    return 0;
  }

  uint8_t *hs_hash = OPENSSL_malloc(EVP_MD_size(hh.digest));
  unsigned int hs_hash_len;
  if (!EVP_DigestFinal_ex(&hh, hs_hash, &hs_hash_len)) {
    return 0;
  }

  const uint8_t *mSS_label;
  size_t mSS_label_len;
  const uint8_t *mES_label;
  size_t mES_label_len;
  if (!tls13_label(&mSS_label, &mSS_label_len, kTLS13LabelmSS,
                   sizeof(kTLS13LabelmSS), hs_hash, hs_hash_len,
                   ssl->hs->key_len) ||
      !tls13_label(&mES_label, &mES_label_len, kTLS13LabelmES,
                   sizeof(kTLS13LabelmES), hs_hash, hs_hash_len,
                   ssl->hs->key_len)) {
    return 0;
  }

  if (!HKDF_expand(mSS, ssl->hs->key_len, digest, ssl->hs->xSS, ssl->hs->key_len,
                   mSS_label, mSS_label_len) ||
      !HKDF_expand(mES, ssl->hs->key_len, digest, ssl->hs->xES, ssl->hs->key_len,
                   mES_label, mES_label_len)) {
    return 0;
  }

  if (ssl->hs->master_secret) {
    return 0;
  }

  ssl->hs->master_secret = OPENSSL_malloc(EVP_MAX_MD_SIZE);
  if (!HKDF_extract(ssl->hs->master_secret, &ssl->hs->key_len,
                    digest, mES, ssl->hs->key_len, mSS, ssl->hs->key_len)) {
    return 0;
  }

  size_t i;
  printf("mSS: ");
  for (i = 0; i < ssl->hs->key_len; i++) {
    printf("%02x", mSS[i]);
  }
  printf("\n");
  printf("mES: ");
  for (i = 0; i < ssl->hs->key_len; i++) {
    printf("%02x", mES[i]);
  }
  printf("\n");
  printf("master secret: ");
  for (i = 0; i < ssl->hs->key_len; i++) {
    printf("%02x", ssl->hs->master_secret[i]);
  }
  printf("\n");


  ssl->hs->traffic_secret = OPENSSL_malloc(EVP_MAX_MD_SIZE);
  const uint8_t *traffic_label;
  size_t traffic_label_len;
  if (!tls13_label(&traffic_label, &traffic_label_len, kTLS13LabelTraffic,
                   sizeof(kTLS13LabelTraffic), hs_hash, hs_hash_len,
                   ssl->hs->key_len) ||
      !HKDF_expand(ssl->hs->traffic_secret, ssl->hs->key_len, digest,
                   ssl->hs->master_secret, ssl->hs->key_len,
                   traffic_label, traffic_label_len)) {
    return 0;
  }

  OPENSSL_free(mSS);
  OPENSSL_free(mES);
  OPENSSL_free(ssl->hs->xSS);
  OPENSSL_free(ssl->hs->xES);
  return 1;
}

int tls13_verify_finished(uint8_t *out, size_t *out_len, SSL *ssl,
                          char is_server) {
  const EVP_MD *digest = ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl));
  uint8_t *key = OPENSSL_malloc(EVP_MAX_MD_SIZE);
  size_t key_len = EVP_MD_size(digest);

  if (key == NULL) {
    return 0;
  }

  const uint8_t *label;
  size_t label_len;
  if (is_server) {
    if (!tls13_label(&label, &label_len, kTLS13LabelServerFinished,
                     sizeof(kTLS13LabelServerFinished),
                     NULL, 0, ssl->hs->key_len)) {
      return 0;
    }
  } else {
    if (!tls13_label(&label, &label_len, kTLS13LabelClientFinished,
                     sizeof(kTLS13LabelClientFinished),
                     NULL, 0, ssl->hs->key_len)) {
      return 0;
    }
  }

  if (!HKDF_expand(key, key_len, digest, ssl->hs->master_secret, ssl->hs->key_len,
                   label, label_len)) {
    return 0;
  }

  unsigned len;
  if (HMAC(digest, key, key_len, ssl->hs->hs_context, ssl->hs->hs_context_len,
           out, &len) == NULL) {
    return 0;
  }
  *out_len = len;

  size_t i;
  printf("HASH: ");
  for (i = 0; i < ssl->hs->hs_context_len; i++) {
    printf("%02x", ssl->hs->hs_context[i]);
  }
  printf("\n");

  printf("BKEY: ");
  for (i = 0; i < ssl->hs->key_len; i++) {
    printf("%02x", ssl->hs->master_secret[i]);
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
