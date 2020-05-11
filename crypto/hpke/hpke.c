// TODO(dmcardle) add boilerplate

#include <assert.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/hmac.h>

#include "../internal.h"
#include "internal.h"

void EVP_HPKE_KEM_init(evp_hpke_kem* kem) {
  kem->kem_group = SSL_CURVE_X25519;
  kem->kem_hkdf_md = EVP_sha256();
  OPENSSL_memset(&kem->kem_sk_e, 0, sizeof(kem->kem_sk_e));
}

void EVP_HPKE_KEM_cleanup(evp_hpke_kem* kem) {}

int EVP_HPKE_CTX_init(evp_hpke_ctx *ctx) {
  EVP_HPKE_KEM_init(&ctx->kem);

  // KDF
  ctx->hkdf_md = EVP_sha256();

  // AEAD
  OPENSSL_memset(&ctx->aead_key, 0, sizeof(ctx->aead_key));
  EVP_AEAD_CTX_zero(&ctx->aead);
  if (!EVP_AEAD_CTX_init(&ctx->aead, EVP_aead_aes_128_gcm(), ctx->aead_key,
                         sizeof(ctx->aead_key), EVP_AEAD_DEFAULT_TAG_LENGTH,
                         NULL)) {
    return 0;
  }

  // Remaining context.
  OPENSSL_memset(&ctx->nonce, 0, sizeof(ctx->nonce));
  OPENSSL_memset(&ctx->exporter_secret, 0, sizeof(ctx->exporter_secret));
  ctx->seq = 0;

  return 1;
}

void EVP_HPKE_CTX_cleanup(evp_hpke_ctx *ctx) {}

