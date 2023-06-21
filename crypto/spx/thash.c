#include "./thash.h"

#include <openssl/base.h>
#include <openssl/digest.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

#include "./params.h"
#include "./util.h"

static void thash(uint8_t *output, const uint8_t *input, size_t input_blocks,
                  const uint8_t pk_seed[SPX_N], uint8_t addr[32]) {
  uint8_t hash[32];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);

  // Process pubseed with padding to full block.
  // TODO: This could be precomputed instead as it will be the same across all
  // hash calls.
  uint8_t padded_pk_seed[64] = {0};
  memcpy(padded_pk_seed, pk_seed, SPX_N);

  SHA256_Update(&sha256, padded_pk_seed, sizeof(padded_pk_seed));
  SHA256_Update(&sha256, addr, SPX_SHA256_ADDR_BYTES);
  SHA256_Update(&sha256, input, input_blocks * SPX_N);

  SHA256_Final(hash, &sha256);
  memcpy(output, hash, SPX_N);
}

void thash_f(uint8_t *output, const uint8_t input[SPX_N],
             const uint8_t pk_seed[SPX_N], uint8_t addr[32]) {
  thash(output, input, 1, pk_seed, addr);
}

void thash_h(uint8_t *output, const uint8_t input[2 * SPX_N],
             const uint8_t pk_seed[SPX_N], uint8_t addr[32]) {
  thash(output, input, 2, pk_seed, addr);
}

void thash_hmsg(uint8_t *output, const uint8_t r[SPX_N],
                const uint8_t pk_seed[SPX_N], const uint8_t pk_root[SPX_N],
                const uint8_t *msg, size_t msg_len) {
  // MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m)
  uint8_t input_buffer[2 * SPX_N + 32 + 4] = {
      0};  // Storing R || PK_SEED || SHA256(..) || 4-byte index
  memcpy(input_buffer, r, SPX_N);
  memcpy(input_buffer + SPX_N, pk_seed, SPX_N);

  // Inner hash
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, r, SPX_N);
  SHA256_Update(&ctx, pk_seed, SPX_N);
  SHA256_Update(&ctx, pk_root, SPX_N);
  SHA256_Update(&ctx, msg, msg_len);
  // Write directly into the input buffer
  SHA256_Final(input_buffer + 2 * SPX_N, &ctx);

  // MGF1-SHA-256
  uint8_t
      output_buffer[3 * 32];  // Need to call SHA256 3 times for message digest.
  SHA256(input_buffer, sizeof(input_buffer), output_buffer);
  input_buffer[2 * SPX_N + 32 + 3] = 1;
  SHA256(input_buffer, sizeof(input_buffer), output_buffer + 32);
  input_buffer[2 * SPX_N + 32 + 3] = 2;
  SHA256(input_buffer, sizeof(input_buffer), output_buffer + 64);

  memcpy(output, output_buffer, SPX_DIGEST_SIZE);
}

void thash_prf(uint8_t *output, const uint8_t pk_seed[SPX_N],
               const uint8_t sk_seed[SPX_N], uint8_t addr[32]) {
  thash(output, sk_seed, 1, pk_seed, addr);
}

void thash_prfmsg(uint8_t *output, const uint8_t sk_prf[SPX_N],
                  const uint8_t opt_rand[SPX_N], const uint8_t *msg,
                  size_t msg_len) {
  unsigned int hmac_len;
  uint8_t hmac_out[32];

  HMAC_CTX ctx;
  // Initialize the HMAC
  HMAC_Init(&ctx, sk_prf, SPX_N, EVP_sha256());
  HMAC_Update(&ctx, opt_rand, SPX_N);
  HMAC_Update(&ctx, msg, msg_len);
  HMAC_Final(&ctx, hmac_out, &hmac_len);
  HMAC_CTX_cleanup(&ctx);

  // Truncate to SPX_N bytes
  memcpy(output, hmac_out, SPX_N);
}

void thash_tl(uint8_t *output, const uint8_t input[SPX_WOTS_BYTES],
              const uint8_t pk_seed[SPX_N], uint8_t addr[32]) {
  thash(output, input, SPX_WOTS_LEN, pk_seed, addr);
}

void thash_tk(uint8_t *output, const uint8_t input[SPX_FORS_TREES * SPX_N],
              const uint8_t pk_seed[SPX_N], uint8_t addr[32]) {
  thash(output, input, SPX_FORS_TREES, pk_seed, addr);
}
