#include "./merkle.h"

#include <string.h>

#include "./address.h"
#include "./params.h"
#include "./thash.h"
#include "./wots.h"

void treehash(uint8_t out_pk[SPX_N], const uint8_t sk_seed[SPX_N],
              uint32_t i /*target node index*/,
              uint32_t z /*target node height*/, const uint8_t pk_seed[SPX_N],
              uint8_t addr[32]) {
  // TODO: Bound checks which are probably not safe, but should never be
  // triggered.
  if (z > SPX_TREE_HEIGHT) {
    return;  // TODO: Should never happen, but we should return error.
  }

  if (i >= (uint32_t)(1 << (SPX_TREE_HEIGHT - z))) {
    return;  // TODO: Should never happen, but we should return error.
  }

  if (z == 0) {
    set_type(addr, SPX_ADDR_TYPE_WOTS);
    set_keypair_addr(addr, i);
    wots_pk_gen(out_pk, sk_seed, pk_seed, addr);
  } else {
    // Stores left node and right node.
    uint8_t nodes[2 * SPX_N];
    treehash(nodes, sk_seed, 2 * i, z - 1, pk_seed, addr);
    treehash(nodes + SPX_N, sk_seed, 2 * i + 1, z - 1, pk_seed, addr);
    set_type(addr, SPX_ADDR_TYPE_HASHTREE);
    set_tree_height(addr, z);
    set_tree_index(addr, i);
    thash_h(out_pk, nodes, pk_seed, addr);
  }
}

void xmss_sign(uint8_t *sig, const uint8_t msg[SPX_N], unsigned int idx,
               const uint8_t sk_seed[SPX_N], const uint8_t pk_seed[SPX_N],
               uint8_t addr[32]) {
  // Build authentication path
  for (size_t j = 0; j < SPX_TREE_HEIGHT; ++j) {
    unsigned int k = (idx >> j) ^ 1;
    treehash(sig + SPX_WOTS_BYTES + j * SPX_N, sk_seed, k, j, pk_seed, addr);
  }

  // Compute WOTS+ signature
  set_type(addr, SPX_ADDR_TYPE_WOTS);
  set_keypair_addr(addr, idx);
  wots_sign(sig, msg, sk_seed, pk_seed, addr);
}

void xmss_pk_from_sig(uint8_t *root, const uint8_t *xmss_sig, unsigned int idx,
                      const uint8_t msg[SPX_N], const uint8_t pk_seed[SPX_N],
                      uint8_t addr[32]) {
  // Stores node[0] and node[1] from Algorithm 10
  uint8_t node[2 * SPX_N];
  uint8_t tmp[2 * SPX_N];
  set_type(addr, SPX_ADDR_TYPE_WOTS);
  set_keypair_addr(addr, idx);
  wots_pk_from_sig(node, xmss_sig, msg, pk_seed, addr);

  const uint8_t *auth = xmss_sig + SPX_WOTS_BYTES;

  set_type(addr, SPX_ADDR_TYPE_HASHTREE);
  set_tree_index(addr, idx);
  for (size_t k = 0; k < SPX_TREE_HEIGHT; ++k) {
    set_tree_height(addr, k + 1);
    // Is even
    if (((idx >> k) & 1) == 0) {
      set_tree_index(addr, get_tree_index(addr) >> 1);
      memcpy(tmp, node, SPX_N);
      memcpy(tmp + SPX_N, auth + k * SPX_N, SPX_N);
      thash_h(node + SPX_N, tmp, pk_seed, addr);
    } else {
      set_tree_index(addr, (get_tree_index(addr) - 1) >> 1);
      memcpy(tmp, auth + k * SPX_N, SPX_N);
      memcpy(tmp + SPX_N, node, SPX_N);
      thash_h(node + SPX_N, tmp, pk_seed, addr);
    }
    memcpy(node, node + SPX_N, SPX_N);
  }
  memcpy(root, node, SPX_N);
}

void ht_sign(uint8_t *sig, const uint8_t message[SPX_N], uint64_t idx_tree,
             uint32_t idx_leaf, const uint8_t sk_seed[SPX_N],
             const uint8_t pk_seed[SPX_N]) {
  uint8_t addr[32] = {0};
  set_tree_addr(addr, idx_tree);

  // Layer 0
  uint8_t sig_tmp[SPX_XMSS_BYTES];
  xmss_sign(sig_tmp, message, idx_leaf, sk_seed, pk_seed, addr);
  memcpy(sig, sig_tmp, sizeof(sig_tmp));

  uint8_t root[SPX_N];
  xmss_pk_from_sig(root, sig_tmp, idx_leaf, message, pk_seed, addr);

  // All other layers
  for (size_t j = 1; j < SPX_D; ++j) {
    idx_leaf = idx_tree % (1 << SPX_TREE_HEIGHT);
    idx_tree = idx_tree >> SPX_TREE_HEIGHT;
    set_layer_addr(addr, j);
    set_tree_addr(addr, idx_tree);
    xmss_sign(sig_tmp, root, idx_leaf, sk_seed, pk_seed, addr);
    memcpy(sig + j * SPX_XMSS_BYTES, sig_tmp, sizeof(sig_tmp));

    if (j < (SPX_D - 1)) {
      xmss_pk_from_sig(root, sig_tmp, idx_leaf, root, pk_seed, addr);
    }
  }
}

int ht_verify(const uint8_t sig[SPX_D * SPX_XMSS_BYTES],
              const uint8_t message[SPX_N], uint64_t idx_tree,
              uint32_t idx_leaf, const uint8_t pk_root[SPX_N],
              const uint8_t pk_seed[SPX_N]) {
  uint8_t addr[32] = {0};
  set_tree_addr(addr, idx_tree);

  uint8_t sig_tmp[SPX_XMSS_BYTES];
  memcpy(sig_tmp, sig, sizeof(sig_tmp));

  uint8_t node[SPX_N];
  xmss_pk_from_sig(node, sig_tmp, idx_leaf, message, pk_seed, addr);

  for (size_t j = 1; j < SPX_D; ++j) {
    idx_leaf = idx_tree % (1 << SPX_TREE_HEIGHT);
    idx_tree = idx_tree >> SPX_TREE_HEIGHT;
    set_layer_addr(addr, j);
    set_tree_addr(addr, idx_tree);
    // Get jth XMSS signature
    memcpy(sig_tmp, sig + j * SPX_XMSS_BYTES, sizeof(sig_tmp));

    xmss_pk_from_sig(node, sig_tmp, idx_leaf, node, pk_seed, addr);
  }
  return memcmp(node, pk_root, SPX_N) == 0;
}
