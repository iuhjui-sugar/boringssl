#include "./address.h"

#include <string.h>

#include "./util.h"

/*
 * Offsets of various fields in the address structure for SPHINCS+-SHA2-128s.
 */

#define SPX_OFFSET_LAYER                              \
  0 /* The byte used to specify the Merkle tree layer \
     */
#define SPX_OFFSET_TREE \
  1 /* The start of the 8 byte field used to specify the tree */
#define SPX_OFFSET_TYPE                                \
  9 /* The byte used to specify the hash type (reason) \
     */
#define SPX_OFFSET_KP_ADDR2                                                   \
  12 /* The high byte used to specify the key pair (which one-time signature) \
      */
#define SPX_OFFSET_KP_ADDR1 13 /* The low byte used to specify the key pair */
#define SPX_OFFSET_CHAIN_ADDR \
  17 /* The byte used to specify the chain address (which Winternitz chain) */
#define SPX_OFFSET_HASH_ADDR                                               \
  21 /* The byte used to specify the hash address (where in the Winternitz \
        chain) */
#define SPX_OFFSET_TREE_HGT                                                    \
  17 /* The byte used to specify the height of this node in the FORS or Merkle \
        tree */
#define SPX_OFFSET_TREE_INDEX                                                 \
  18 /* The start of the 4 byte field used to specify the node in the FORS or \
        Merkle tree */

void set_chain_addr(uint32_t addr[8], uint32_t chain) {
  ((uint8_t *)addr)[SPX_OFFSET_CHAIN_ADDR] = (uint8_t)chain;
}

void set_hash_addr(uint32_t addr[8], uint32_t hash) {
  ((uint8_t *)addr)[SPX_OFFSET_HASH_ADDR] = (uint8_t)hash;
}

void set_keypair_addr(uint32_t addr[8], uint32_t keypair) {
  ((uint8_t *)addr)[SPX_OFFSET_KP_ADDR2] = (uint8_t)(keypair >> 8);
  ((uint8_t *)addr)[SPX_OFFSET_KP_ADDR1] = (uint8_t)keypair;
}

void copy_keypair_addr(uint32_t out[8], const uint32_t in[8]) {
  memcpy(out, in, SPX_OFFSET_TREE + 8);
  ((uint8_t *)out)[SPX_OFFSET_KP_ADDR2] = ((uint8_t *)in)[SPX_OFFSET_KP_ADDR2];
  ((uint8_t *)out)[SPX_OFFSET_KP_ADDR1] = ((uint8_t *)in)[SPX_OFFSET_KP_ADDR1];
}

void set_layer_addr(uint32_t addr[8], uint32_t layer) {
  ((uint8_t *)addr)[SPX_OFFSET_LAYER] = (uint8_t)layer;
}

void set_tree_addr(uint32_t addr[8], uint64_t tree) {
  to_bytes(&((uint8_t *)addr)[SPX_OFFSET_TREE], 8, tree);
}

void set_type(uint32_t addr[8], uint32_t type) {
  // NIST draft relies on this setting parts of the address to 0, so we do it
  // here to avoid confusion.
  //
  // The behavior here is only correct for the SHA2 instantiations.
  memset((uint8_t *)(addr) + 10, 0, 12);
  ((uint8_t *)addr)[SPX_OFFSET_TYPE] = (uint8_t)type;
}

void set_tree_height(uint32_t addr[8], uint32_t tree_height) {
  ((uint8_t *)addr)[SPX_OFFSET_TREE_HGT] = (uint8_t)tree_height;
}

void set_tree_index(uint32_t addr[8], uint32_t tree_index) {
  uint32_to_bytes(&((uint8_t *)addr)[SPX_OFFSET_TREE_INDEX], tree_index);
}

uint32_t get_tree_index(uint32_t addr[8]) {
  return to_uint32((((uint8_t *)addr) + SPX_OFFSET_TREE_INDEX));
}