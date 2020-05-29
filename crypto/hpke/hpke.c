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
#include <string.h>

#include <openssl/err.h>
#include <openssl/hmac.h>

#include "../internal.h"
#include "internal.h"

typedef enum evp_hpke_mode {
  EVP_HPKE_MODE_BASE = 0,  // We only support |HPKE_MODE_BASE|.
  EVP_HPKE_MODE_PSK = 1,
  EVP_HPKE_MODE_AUTH = 2,
  EVP_HPKE_MODE_AUTH_PSK = 3,
} evp_hpke_mode;

void EVP_HPKE_KEM_init(evp_hpke_kem *kem);
void EVP_HPKE_KEM_cleanup(evp_hpke_kem *kem);

//
// EVP_HPKE_KEM
//

void EVP_HPKE_KEM_init(evp_hpke_kem* kem) {
  kem->kem_group = SSL_CURVE_X25519;
  kem->kem_hkdf_md = EVP_sha256();
  OPENSSL_memset(&kem->kem_sk_e, 0, sizeof(kem->kem_sk_e));
}

void EVP_HPKE_KEM_cleanup(evp_hpke_kem* kem) {}

//
// EVP_HPKE_CTX
//

int setup_base_common(EVP_HPKE_CTX *ctx) {
  uint8_t aead_key[EVP_AEAD_MAX_KEY_LENGTH];

  OPENSSL_memset(aead_key, 0, sizeof(aead_key));

  if (!EVP_AEAD_CTX_init(&ctx->aead, EVP_aead_aes_128_gcm(), aead_key,
                         sizeof(aead_key), EVP_AEAD_DEFAULT_TAG_LENGTH,
                         NULL)) {
    return 0;
  }
  return 1;
}

void EVP_HPKE_CTX_init(EVP_HPKE_CTX *ctx) {
  evp_hpke_kem kem;
  EVP_HPKE_KEM_init(&kem);

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
