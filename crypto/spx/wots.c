#include "./wots.h"

#include <openssl/base.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "./address.h"
#include "./params.h"
#include "./thash.h"
#include "./util.h"

// Chaining function used in WOTS+.
static void chain(uint8_t *output, const uint8_t *input, unsigned int start,
                  unsigned int steps, const uint8_t *pub_seed,
                  uint8_t addr[32]) {
  memcpy(output, input, SPX_N);

  // TODO: start + steps could overflow, but these values are very small for
  // all parameters which are feasible in practice.
  for (unsigned int i = start; i < (start + steps) && i < SPX_WOTS_W; ++i) {
    set_hash_addr(addr, i);
    thash_f(output, output, pub_seed, addr);
  }
}

void wots_pk_from_sig(uint8_t *pk, const uint8_t *sig, const uint8_t *msg,
                      const uint8_t pub_seed[SPX_N], uint8_t addr[32]) {
  uint8_t tmp[SPX_WOTS_BYTES];
  uint8_t wots_pk_addr[32];
  memcpy(wots_pk_addr, addr, sizeof(wots_pk_addr));

  // Convert message to base w
  uint32_t base_w_msg[SPX_WOTS_LEN];
  base_b(base_w_msg, SPX_WOTS_LEN1, msg, SPX_WOTS_W);

  // Compute checksum
  unsigned int csum = 0;
  for (int i = 0; i < SPX_WOTS_LEN1; ++i) {
    csum += SPX_WOTS_W - 1 - base_w_msg[i];
  }

  // Convert csum to base w
  uint8_t csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOG_W + 7) / 8];
  csum = csum << (8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOG_W)) % 8);
  to_bytes(csum_bytes, sizeof(csum_bytes), csum);

  // Write the base w representation of csum to the end of the message.
  base_b(base_w_msg + SPX_WOTS_LEN1, SPX_WOTS_LEN2, csum_bytes, SPX_WOTS_W);

  // Compute chains
  for (int i = 0; i < SPX_WOTS_LEN; ++i) {
    set_chain_addr(addr, i);
    chain(tmp + i * SPX_N, sig + i * SPX_N, base_w_msg[i],
          SPX_WOTS_W - 1 - base_w_msg[i], pub_seed, addr);
  }

  // Compress pk
  set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);
  copy_keypair_addr(wots_pk_addr, addr);
  thash_tl(pk, tmp, pub_seed, wots_pk_addr);
}

void wots_pk_gen(uint8_t *pk, const uint8_t sk_seed[SPX_N],
                 const uint8_t pub_seed[SPX_N], uint8_t addr[32]) {
  uint8_t tmp[SPX_WOTS_BYTES];
  uint8_t tmp_sk[SPX_N];
  uint8_t wots_pk_addr[32], sk_addr[32];
  memcpy(wots_pk_addr, addr, sizeof(wots_pk_addr));
  memcpy(sk_addr, addr, sizeof(sk_addr));

  set_type(sk_addr, SPX_ADDR_TYPE_WOTSPRF);
  copy_keypair_addr(sk_addr, addr);

  for (int i = 0; i < SPX_WOTS_LEN; ++i) {
    set_chain_addr(sk_addr, i);
    thash_prf(tmp_sk, pub_seed, sk_seed, sk_addr);
    set_chain_addr(addr, i);
    chain(tmp + i * SPX_N, tmp_sk, 0, SPX_WOTS_W - 1, pub_seed, addr);
  }

  // Compress pk
  set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);
  copy_keypair_addr(wots_pk_addr, addr);
  thash_tl(pk, tmp, pub_seed, wots_pk_addr);
}

void wots_sign(uint8_t *sig, const uint8_t msg[SPX_N],
               const uint8_t sk_seed[SPX_N], const uint8_t pub_seed[SPX_N],
               uint8_t addr[32]) {
  // Convert message to base w
  uint32_t base_w_msg[SPX_WOTS_LEN];
  base_b(base_w_msg, SPX_WOTS_LEN1, msg, SPX_WOTS_W);

  // Compute checksum
  unsigned int csum = 0;
  for (int i = 0; i < SPX_WOTS_LEN1; ++i) {
    csum += SPX_WOTS_W - 1 - base_w_msg[i];
  }

  // Convert csum to base w
  uint8_t csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOG_W + 7) / 8];
  csum = csum << (8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOG_W)) % 8);
  to_bytes(csum_bytes, sizeof(csum_bytes), csum);

  // Write the base w representation of csum to the end of the message.
  base_b(base_w_msg + SPX_WOTS_LEN1, SPX_WOTS_LEN2, csum_bytes, SPX_WOTS_W);

  // Compute chains
  uint8_t tmp_sk[SPX_N];
  uint8_t sk_addr[32];
  memcpy(sk_addr, addr, sizeof(sk_addr));
  set_type(sk_addr, SPX_ADDR_TYPE_WOTSPRF);
  copy_keypair_addr(sk_addr, addr);

  for (int i = 0; i < SPX_WOTS_LEN; ++i) {
    set_chain_addr(sk_addr, i);
    thash_prf(tmp_sk, pub_seed, sk_seed, sk_addr);
    set_chain_addr(addr, i);
    chain(sig + i * SPX_N, tmp_sk, 0, base_w_msg[i], pub_seed, addr);
  }
}
