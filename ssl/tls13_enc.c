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

enum tls13_record_type_t {
  tls13_type_handshake,
  tls13_type_data,
  tls13_type_early_handshake,
  tls13_type_early_data,
};

enum tls13_record_key_t {
  tls13_record_server_key,
  tls13_record_server_iv,
  tls13_record_client_key,
  tls13_record_client_iv,
};

static void tls13_label(uint8_t **out, size_t *out_len,
                        enum tls13_record_type_t type,
                        enum tls13_record_key_t source,
                        size_t hkdf_len, uint8_t *hash, size_t hash_len) {
  size_t label_len = sizeof(kTLS13LabelVersion) + sizeof(kTLS13LabelPhase);
  switch (type) {
    case tls13_type_handshake:
      label_len += sizeof(kTLS13LabelHandshake); break;
    case tls13_type_data:
      label_len += sizeof(kTLS13LabelData); break;
    case tls13_type_early_handshake:
      label_len += sizeof(kTLS13LabelEarlyHandshake); break;
    case tls13_type_early_data:
      label_len += sizeof(kTLS13LabelEarlyData); break;
  }

  switch (source) {
    case tls13_record_server_key: label_len += sizeof(kTLS13LabelServerKey); break;
    case tls13_record_server_iv: label_len += sizeof(kTLS13LabelServerIV); break;
    case tls13_record_client_key: label_len += sizeof(kTLS13LabelClientKey); break;
    case tls13_record_client_iv: label_len += sizeof(kTLS13LabelClientIV); break;
  }

  uint8_t *lbl = OPENSSL_malloc(2 + 1 + label_len + 1 + hash_len);
  size_t offset = 0;

  lbl[0] = (uint8_t)((hkdf_len >> 8) & 0xff);
  lbl[1] = (uint8_t)(hkdf_len & 0xff);
  lbl[2] = label_len;
  offset += 3;

  memcpy(&lbl[offset], kTLS13LabelVersion, sizeof(kTLS13LabelVersion));
  offset += sizeof(kTLS13LabelVersion);
  switch (type) {
    case tls13_type_handshake:
      memcpy(&lbl[offset], kTLS13LabelHandshake, sizeof(kTLS13LabelHandshake));
      offset += sizeof(kTLS13LabelHandshake); break;
    case tls13_type_data:
      memcpy(&lbl[offset], kTLS13LabelData, sizeof(kTLS13LabelData));
      offset += sizeof(kTLS13LabelData); break;
    case tls13_type_early_handshake:
      memcpy(&lbl[offset], kTLS13LabelEarlyHandshake,
             sizeof(kTLS13LabelEarlyHandshake));
      offset += sizeof(kTLS13LabelEarlyHandshake); break;
    case tls13_type_early_data:
      memcpy(&lbl[offset], kTLS13LabelEarlyData, sizeof(kTLS13LabelEarlyData));
      offset += sizeof(kTLS13LabelEarlyData); break;
  }
  memcpy(&lbl[offset], kTLS13LabelPhase, sizeof(kTLS13LabelPhase));
  offset += sizeof(kTLS13LabelPhase);
  switch (source) {
    case tls13_record_server_key:
      memcpy(&lbl[offset], kTLS13LabelServerKey, sizeof(kTLS13LabelServerKey));
      offset += sizeof(kTLS13LabelServerKey); break;
    case tls13_record_server_iv:
      memcpy(&lbl[offset], kTLS13LabelServerIV, sizeof(kTLS13LabelServerIV));
      offset += sizeof(kTLS13LabelServerIV); break;
    case tls13_record_client_key:
      memcpy(&lbl[offset], kTLS13LabelClientKey, sizeof(kTLS13LabelClientKey));
      offset += sizeof(kTLS13LabelClientKey); break;
    case tls13_record_client_iv:
      memcpy(&lbl[offset], kTLS13LabelClientIV, sizeof(kTLS13LabelClientIV));
      offset += sizeof(kTLS13LabelClientIV); break;
  }

  lbl[offset] = hash_len;
  offset += 1;

  memcpy(&lbl[offset], hash, hash_len);
  offset += hash_len;

  *out = lbl;
  *out_len = offset;
}

int tls13_update_handshake_keys(SSL *ssl, uint8_t *es, size_t es_len) {
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

  uint8_t *hs_hash = OPENSSL_malloc(EVP_MD_size(ssl->s3->handshake_hash.digest));
  unsigned int hs_hash_len;
  if (!EVP_DigestFinal_ex(&ssl->s3->handshake_hash, hs_hash, &hs_hash_len)) {
    return 0;
  }

  // Generate xES = HKDF-Extract(0, ES)
  // L = EVP_AEAD_key_length/EVP_AEAD_nonce_length
  // handshakeKeys = {HKDF(xES, "TLS 1.3, handshake key expansion, PURPOSE", hs_hash, L)}
  // aead = ???(handshakeKeys, ssl->cipher_suite)
  size_t secret_len;
  uint8_t *secret = OPENSSL_malloc(secret_len);
  if (!HKDF_extract(secret, &secret_len, digest, es, es_len, NULL, 0)) {
    return 0;
  }

  uint8_t *write_key = OPENSSL_malloc(key_len);
  uint8_t *write_iv = OPENSSL_malloc(iv_len);
  uint8_t *read_key = OPENSSL_malloc(key_len);
  uint8_t *read_iv = OPENSSL_malloc(iv_len);

  enum tls13_record_type_t key_type = tls13_type_handshake;

  uint8_t *client_key_label;
  size_t client_key_label_len;
  uint8_t *client_iv_label;
  size_t client_iv_label_len;
  uint8_t *server_key_label;
  size_t server_key_label_len;
  uint8_t *server_iv_label;
  size_t server_iv_label_len;
  tls13_label(&client_key_label, &client_key_label_len, key_type,
              tls13_record_client_key, key_len, hs_hash, hs_hash_len);
  tls13_label(&client_iv_label, &client_iv_label_len, key_type,
              tls13_record_client_iv, iv_len, hs_hash, hs_hash_len);
  tls13_label(&server_key_label, &server_key_label_len, key_type,
              tls13_record_server_key, key_len, hs_hash, hs_hash_len);
  tls13_label(&server_iv_label, &server_iv_label_len, key_type,
              tls13_record_server_iv, iv_len, hs_hash, hs_hash_len);


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
  printf("ES: ");
  for (i = 0; i < es_len; i++) {
    printf("%02x", es[i]);
  }
  printf("\n");
  printf("xES: ");
  for (i = 0; i < secret_len; i++) {
    printf("%02x", secret[i]);
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
