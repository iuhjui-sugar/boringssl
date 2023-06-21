/* Copyright (c) 2023, Google LLC
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
#ifndef OPENSSL_HEADER_CRYPTO_SPX_ADDRESS_H
#define OPENSSL_HEADER_CRYPTO_SPX_ADDRESS_H

#include <openssl/base.h>

#define SPX_ADDR_TYPE_WOTS 0
#define SPX_ADDR_TYPE_WOTSPK 1
#define SPX_ADDR_TYPE_HASHTREE 2
#define SPX_ADDR_TYPE_FORSTREE 3
#define SPX_ADDR_TYPE_FORSPK 4
#define SPX_ADDR_TYPE_WOTSPRF 5
#define SPX_ADDR_TYPE_FORSPRF 6

#if defined(__cplusplus)
extern "C" {
#endif

void set_chain_addr(uint32_t addr[8], uint32_t chain);
void set_hash_addr(uint32_t addr[8], uint32_t hash);
void set_keypair_addr(uint32_t addr[8], uint32_t keypair);
void set_layer_addr(uint32_t addr[8], uint32_t layer);
void set_tree_addr(uint32_t addr[8], uint64_t tree);
void set_type(uint32_t addr[8], uint32_t type);
void set_tree_height(uint32_t addr[8], uint32_t tree_height);
void set_tree_index(uint32_t addr[8], uint32_t tree_index);
void copy_keypair_addr(uint32_t out[8], const uint32_t in[8]);

uint32_t get_tree_index(uint32_t addr[8]);

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CRYPTO_SPX_ADDRESS_H
