#include <openssl/rand.h>
#include <openssl/spx.h>
#include <string.h>

#include "./address.h"
#include "./fors.h"
#include "./merkle.h"
#include "./params.h"
#include "./thash.h"
#include "./util.h"

void spx_generate_key(uint8_t out_public_key[SPX_PUBLIC_KEY_BYTES],
                      uint8_t out_secret_key[SPX_SECRET_KEY_BYTES]) {
  uint8_t seed[3 * SPX_N];
  RAND_bytes(seed, 3 * SPX_N);
  spx_generate_key_from_seed(out_public_key, out_secret_key, seed);
}

void spx_generate_key_from_seed(uint8_t out_public_key[SPX_PUBLIC_KEY_BYTES],
                                uint8_t out_secret_key[SPX_SECRET_KEY_BYTES],
                                const uint8_t seed[3 * SPX_N]) {
  // Initialize SK.seed || SK.prf || PK.seed from seed.
  memcpy(out_secret_key, seed, 3 * SPX_N);

  // Initialize PK.seed from seed.
  memcpy(out_public_key, seed + 2 * SPX_N, SPX_N);

  uint32_t addr[8] = {0};
  set_layer_addr(addr, SPX_D - 1);

  // Set PK.root
  treehash(out_public_key + SPX_N, out_secret_key, 0, SPX_TREE_HEIGHT,
           out_public_key, addr);
  memcpy(out_secret_key + 3 * SPX_N, out_public_key + SPX_N, SPX_N);
}

void spx_sign(uint8_t out_signature[SPX_SIGNATURE_BYTES],
              const uint8_t secret_key[SPX_SECRET_KEY_BYTES],
              const uint8_t *msg, size_t msg_len, bool randomized) {
  uint32_t addr[8] = {0};
  const uint8_t *sk_seed = secret_key;
  const uint8_t *sk_prf = secret_key + SPX_N;
  const uint8_t *pk_seed = secret_key + 2 * SPX_N;
  const uint8_t *pk_root = secret_key + 3 * SPX_N;

  uint8_t opt_rand[SPX_N] = {0};

  if (randomized) {
    RAND_bytes(opt_rand, SPX_N);
  } else {
    memcpy(opt_rand, pk_seed, SPX_N);
  }

  // Derive randomizer r and copy it to signature.
  uint8_t r[SPX_N];
  thash_prfmsg(r, sk_prf, opt_rand, msg, msg_len);
  memcpy(out_signature, r, SPX_N);

  uint8_t digest[SPX_DIGEST_SIZE];
  thash_hmsg(digest, r, pk_seed, pk_root, msg, msg_len);

  uint8_t fors_digest[SPX_FORS_MSG_BYTES];
  memcpy(fors_digest, digest, SPX_FORS_MSG_BYTES);

  uint8_t *tmp_idx_tree = digest + SPX_FORS_MSG_BYTES;
  uint8_t *tmp_idx_leaf = tmp_idx_tree + SPX_TREE_BYTES;

  uint64_t idx_tree = to_uint64(tmp_idx_tree, SPX_TREE_BYTES);
  idx_tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);

  uint32_t idx_leaf = (uint32_t)to_uint64(tmp_idx_leaf, SPX_LEAF_BYTES);
  idx_leaf &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);

  set_tree_addr(addr, idx_tree);
  set_type(addr, SPX_ADDR_TYPE_FORSTREE);
  set_keypair_addr(addr, idx_leaf);

  fors_sign(out_signature + SPX_N, fors_digest, sk_seed, pk_seed, addr);

  uint8_t pk_fors[SPX_N];
  fors_pk_from_sig(pk_fors, out_signature + SPX_N, fors_digest, pk_seed, addr);

  ht_sign(out_signature + SPX_N + SPX_FORS_BYTES, pk_fors, idx_tree, idx_leaf,
          sk_seed, pk_seed);
}

int spx_verify(const uint8_t signature[SPX_SIGNATURE_BYTES],
               const uint8_t public_key[SPX_SECRET_KEY_BYTES],
               const uint8_t *msg, size_t msg_len) {
  uint32_t addr[8] = {0};
  const uint8_t *pk_seed = public_key;
  const uint8_t *pk_root = public_key + SPX_N;

  const uint8_t *r = signature;
  const uint8_t *sig_fors = signature + SPX_N;
  const uint8_t *sig_ht = sig_fors + SPX_FORS_BYTES;

  uint8_t digest[SPX_DIGEST_SIZE];
  thash_hmsg(digest, r, pk_seed, pk_root, msg, msg_len);

  uint8_t fors_digest[SPX_FORS_MSG_BYTES];
  memcpy(fors_digest, digest, SPX_FORS_MSG_BYTES);

  uint8_t *tmp_idx_tree = digest + SPX_FORS_MSG_BYTES;
  uint8_t *tmp_idx_leaf = tmp_idx_tree + SPX_TREE_BYTES;

  uint64_t idx_tree = to_uint64(tmp_idx_tree, SPX_TREE_BYTES);
  idx_tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);

  uint32_t idx_leaf = (uint32_t)to_uint64(tmp_idx_leaf, SPX_LEAF_BYTES);
  idx_leaf &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);

  set_tree_addr(addr, idx_tree);
  set_type(addr, SPX_ADDR_TYPE_FORSTREE);
  set_keypair_addr(addr, idx_leaf);

  uint8_t pk_fors[SPX_N];
  fors_pk_from_sig(pk_fors, sig_fors, fors_digest, pk_seed, addr);

  return ht_verify(sig_ht, pk_fors, idx_tree, idx_leaf, pk_root, pk_seed);
}
