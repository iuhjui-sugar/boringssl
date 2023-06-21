#include "./fors.h"

#include <string.h>

#include "./address.h"
#include "./params.h"
#include "./thash.h"
#include "./util.h"

void fors_sk_gen(uint8_t *fors_sk, unsigned int idx,
                 const uint8_t sk_seed[SPX_N], const uint8_t pk_seed[SPX_N],
                 uint8_t addr[32]) {
  uint8_t sk_addr[32];
  memcpy(sk_addr, addr, sizeof(sk_addr));

  set_type(sk_addr, SPX_ADDR_TYPE_FORSPRF);
  copy_keypair_addr(sk_addr, addr);
  set_tree_index(sk_addr, idx);
  thash_prf(fors_sk, pk_seed, sk_seed, sk_addr);
}

void fors_treehash(uint8_t root_node[SPX_N], const uint8_t sk_seed[SPX_N],
                   uint32_t i /*target node index*/,
                   uint32_t z /*target node height*/,
                   const uint8_t pk_seed[SPX_N], uint8_t addr[32]) {
  // TODO: Bound checks which are probably not safe, but should never be
  // triggered.
  if (z > SPX_FORS_HEIGHT) {
    return;  // TODO: Should never happen, but we should return error.
  }

  if (i >= (uint32_t)(SPX_FORS_TREES * (1 << (SPX_FORS_HEIGHT - z)))) {
    return;  // TODO: Should never happen, but we should return error.
  }

  if (z == 0) {
    uint8_t sk[SPX_N];
    set_tree_height(addr, 0);
    set_tree_index(addr, i);
    fors_sk_gen(sk, i, sk_seed, pk_seed, addr);
    thash_f(root_node, sk, pk_seed, addr);
  } else {
    // Stores left node and right node.
    uint8_t nodes[2 * SPX_N];
    fors_treehash(nodes, sk_seed, 2 * i, z - 1, pk_seed, addr);
    fors_treehash(nodes + SPX_N, sk_seed, 2 * i + 1, z - 1, pk_seed, addr);
    set_tree_height(addr, z);
    set_tree_index(addr, i);
    thash_h(root_node, nodes, pk_seed, addr);
  }
}

void fors_sign(uint8_t *fors_sig, const uint8_t message[SPX_FORS_MSG_BYTES],
               const uint8_t sk_seed[SPX_N], const uint8_t pk_seed[SPX_N],
               uint8_t addr[32]) {
  uint32_t indices[SPX_FORS_TREES];

  // Derive FORS indices compatible with the NIST changes.
  base_b(indices, SPX_FORS_TREES, message, (1 << SPX_FORS_HEIGHT));

  for (size_t i = 0; i < SPX_FORS_TREES; ++i) {
    set_tree_height(addr, 0);
    // Write the FORS secret key element to the correct position.
    fors_sk_gen(fors_sig + i * SPX_N * (SPX_FORS_HEIGHT + 1),
                i * (1 << SPX_FORS_HEIGHT) + indices[i], sk_seed, pk_seed,
                addr);
    for (size_t j = 0; j < SPX_FORS_HEIGHT; ++j) {
      size_t s = (indices[i] / (1 << j)) ^ 1;
      // Write the FORS auth path element to the correct position.
      fors_treehash(fors_sig + SPX_N * (i * (SPX_FORS_HEIGHT + 1) + j + 1),
                    sk_seed, i * (1 << (SPX_FORS_HEIGHT - j)) + s, j, pk_seed,
                    addr);
    }
  }
}

void fors_pk_from_sig(uint8_t *fors_pk, const uint8_t fors_sig[SPX_FORS_BYTES],
                      const uint8_t message[SPX_FORS_MSG_BYTES],
                      const uint8_t pk_seed[SPX_N], uint8_t addr[32]) {
  uint32_t indices[SPX_FORS_TREES];
  uint8_t tmp[2 * SPX_N];
  uint8_t roots[SPX_FORS_TREES * SPX_N];

  // Derive FORS indices compatible with the NIST changes.
  base_b(indices, SPX_FORS_TREES, message, (1 << SPX_FORS_HEIGHT));

  for (size_t i = 0; i < SPX_FORS_TREES; ++i) {
    // Pointer to current sk and authentication path
    const uint8_t *sk = fors_sig + i * SPX_N * (SPX_FORS_HEIGHT + 1);
    const uint8_t *auth = fors_sig + i * SPX_N * (SPX_FORS_HEIGHT + 1) + SPX_N;
    uint8_t nodes[2 * SPX_N];

    set_tree_height(addr, 0);
    set_tree_index(addr, (i * (1 << SPX_FORS_HEIGHT)) + indices[i]);

    thash_f(nodes, sk, pk_seed, addr);

    for (size_t j = 0; j < SPX_FORS_HEIGHT; ++j) {
      set_tree_height(addr, j + 1);

      // Even node
      if (((indices[i] / (1 << j)) % 2) == 0) {
        set_tree_index(addr, get_tree_index(addr) / 2);
        memcpy(tmp, nodes, SPX_N);
        memcpy(tmp + SPX_N, auth + j * SPX_N, SPX_N);
        thash_h(nodes + SPX_N, tmp, pk_seed, addr);
      } else {
        set_tree_index(addr, (get_tree_index(addr) - 1) / 2);
        memcpy(tmp, auth + j * SPX_N, SPX_N);
        memcpy(tmp + SPX_N, nodes, SPX_N);
        thash_h(nodes + SPX_N, tmp, pk_seed, addr);
      }
      memcpy(nodes, nodes + SPX_N, SPX_N);
    }
    memcpy(roots + i * SPX_N, nodes, SPX_N);
  }

  uint8_t forspk_addr[32];
  memcpy(forspk_addr, addr, sizeof(forspk_addr));
  set_type(forspk_addr, SPX_ADDR_TYPE_FORSPK);
  copy_keypair_addr(forspk_addr, addr);
  thash_tk(fors_pk, roots, pk_seed, forspk_addr);
}
