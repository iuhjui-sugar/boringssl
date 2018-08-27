/* Copyright (c) 2018, Google Inc.
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

// Like boringssl_prefix_symbols.h, but included by .S files.

#ifndef BORINGSSL_HEADER_BORINGSSL_PREFIX_SYMBOLS_ASM_H
#define BORINGSSL_HEADER_BORINGSSL_PREFIX_SYMBOLS_ASM_H
#if defined(BORINGSSL_PREFIX)

#if !defined(__APPLE__)
// On non-Mac platforms, just use boringssl_prefix_symbols.h
#include <openssl/boringssl_prefix_symbols.h>
#else

// On Mac, we need to treat assembly symbols differently than we treat other
// symbols (see boringssl_prefix_symbols.h). The Mac linker expects symbols to
// be prefixed with an underscore. Knowing this, the Perl scripts that generate
// the .S files generate them with function names that are prefixed with an
// underscore. Thus, doing something like '#define FOO bar' (as we do in
// boringssl_prefix_symbols.h) won't work to rename an assembly function 'FOO'
// since it will be written in the .S file as '_FOO'. Thus, on Mac, in addition
// to replacing assembly symbol FOO with BORINGSSL_PREFIX_FOO (which we still
// need to do since assembly symbols are referenced in C code), we replace _FOO
// with _BORINGSSL_PREFIX_FOO so that the .S file is properly modified.
//
// See boringssl_prefix_symbols.h for an explanation of how this macro works.
#define __PREFIX_MAC_ASM(a, b) __PREFIX_MAC_ASM_INNER(a, b)
#define __PREFIX_MAC_ASM_INNER(a, b) _ ## a ## b

#define _CRYPTO_rdrand __PREFIX_MAC_ASM(BORINGSSL_PREFIX, CRYPTO_rdrand)
#define _CRYPTO_rdrand_multiple8_buf __PREFIX_MAC_ASM(BORINGSSL_PREFIX, CRYPTO_rdrand_multiple8_buf)
#define _ChaCha20_ctr32 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, ChaCha20_ctr32)
#define _aes128gcmsiv_aes_ks __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes128gcmsiv_aes_ks)
#define _aes128gcmsiv_aes_ks_enc_x1 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes128gcmsiv_aes_ks_enc_x1)
#define _aes128gcmsiv_dec __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes128gcmsiv_dec)
#define _aes128gcmsiv_ecb_enc_block __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes128gcmsiv_ecb_enc_block)
#define _aes128gcmsiv_enc_msg_x4 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes128gcmsiv_enc_msg_x4)
#define _aes128gcmsiv_enc_msg_x8 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes128gcmsiv_enc_msg_x8)
#define _aes128gcmsiv_kdf __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes128gcmsiv_kdf)
#define _aes256gcmsiv_aes_ks __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes256gcmsiv_aes_ks)
#define _aes256gcmsiv_aes_ks_enc_x1 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes256gcmsiv_aes_ks_enc_x1)
#define _aes256gcmsiv_dec __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes256gcmsiv_dec)
#define _aes256gcmsiv_ecb_enc_block __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes256gcmsiv_ecb_enc_block)
#define _aes256gcmsiv_enc_msg_x4 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes256gcmsiv_enc_msg_x4)
#define _aes256gcmsiv_enc_msg_x8 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes256gcmsiv_enc_msg_x8)
#define _aes256gcmsiv_kdf __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes256gcmsiv_kdf)
#define _aes_hw_cbc_encrypt __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes_hw_cbc_encrypt)
#define _aes_hw_ctr32_encrypt_blocks __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes_hw_ctr32_encrypt_blocks)
#define _aes_hw_decrypt __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes_hw_decrypt)
#define _aes_hw_ecb_encrypt __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes_hw_ecb_encrypt)
#define _aes_hw_encrypt __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes_hw_encrypt)
#define _aes_hw_set_decrypt_key __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes_hw_set_decrypt_key)
#define _aes_hw_set_encrypt_key __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes_hw_set_encrypt_key)
#define _aes_nohw_cbc_encrypt __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes_nohw_cbc_encrypt)
#define _aes_nohw_decrypt __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes_nohw_decrypt)
#define _aes_nohw_encrypt __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes_nohw_encrypt)
#define _aes_nohw_set_decrypt_key __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes_nohw_set_decrypt_key)
#define _aes_nohw_set_encrypt_key __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aes_nohw_set_encrypt_key)
#define _aesgcmsiv_htable6_init __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aesgcmsiv_htable6_init)
#define _aesgcmsiv_htable_init __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aesgcmsiv_htable_init)
#define _aesgcmsiv_htable_polyval __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aesgcmsiv_htable_polyval)
#define _aesgcmsiv_polyval_horner __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aesgcmsiv_polyval_horner)
#define _aesni_gcm_decrypt __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aesni_gcm_decrypt)
#define _aesni_gcm_encrypt __PREFIX_MAC_ASM(BORINGSSL_PREFIX, aesni_gcm_encrypt)
#define _bn_from_montgomery __PREFIX_MAC_ASM(BORINGSSL_PREFIX, bn_from_montgomery)
#define _bn_gather5 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, bn_gather5)
#define _bn_mul_mont __PREFIX_MAC_ASM(BORINGSSL_PREFIX, bn_mul_mont)
#define _bn_mul_mont_gather5 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, bn_mul_mont_gather5)
#define _bn_power5 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, bn_power5)
#define _bn_scatter5 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, bn_scatter5)
#define _bsaes_cbc_encrypt __PREFIX_MAC_ASM(BORINGSSL_PREFIX, bsaes_cbc_encrypt)
#define _bsaes_ctr32_encrypt_blocks __PREFIX_MAC_ASM(BORINGSSL_PREFIX, bsaes_ctr32_encrypt_blocks)
#define _chacha20_poly1305_open __PREFIX_MAC_ASM(BORINGSSL_PREFIX, chacha20_poly1305_open)
#define _chacha20_poly1305_seal __PREFIX_MAC_ASM(BORINGSSL_PREFIX, chacha20_poly1305_seal)
#define _ecp_nistz256_mul_mont __PREFIX_MAC_ASM(BORINGSSL_PREFIX, ecp_nistz256_mul_mont)
#define _ecp_nistz256_neg __PREFIX_MAC_ASM(BORINGSSL_PREFIX, ecp_nistz256_neg)
#define _ecp_nistz256_ord_mul_mont __PREFIX_MAC_ASM(BORINGSSL_PREFIX, ecp_nistz256_ord_mul_mont)
#define _ecp_nistz256_ord_sqr_mont __PREFIX_MAC_ASM(BORINGSSL_PREFIX, ecp_nistz256_ord_sqr_mont)
#define _ecp_nistz256_point_add __PREFIX_MAC_ASM(BORINGSSL_PREFIX, ecp_nistz256_point_add)
#define _ecp_nistz256_point_add_affine __PREFIX_MAC_ASM(BORINGSSL_PREFIX, ecp_nistz256_point_add_affine)
#define _ecp_nistz256_point_double __PREFIX_MAC_ASM(BORINGSSL_PREFIX, ecp_nistz256_point_double)
#define _ecp_nistz256_select_w5 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, ecp_nistz256_select_w5)
#define _ecp_nistz256_select_w7 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, ecp_nistz256_select_w7)
#define _ecp_nistz256_sqr_mont __PREFIX_MAC_ASM(BORINGSSL_PREFIX, ecp_nistz256_sqr_mont)
#define _gcm_ghash_4bit __PREFIX_MAC_ASM(BORINGSSL_PREFIX, gcm_ghash_4bit)
#define _gcm_ghash_avx __PREFIX_MAC_ASM(BORINGSSL_PREFIX, gcm_ghash_avx)
#define _gcm_ghash_clmul __PREFIX_MAC_ASM(BORINGSSL_PREFIX, gcm_ghash_clmul)
#define _gcm_gmult_4bit __PREFIX_MAC_ASM(BORINGSSL_PREFIX, gcm_gmult_4bit)
#define _gcm_gmult_avx __PREFIX_MAC_ASM(BORINGSSL_PREFIX, gcm_gmult_avx)
#define _gcm_gmult_clmul __PREFIX_MAC_ASM(BORINGSSL_PREFIX, gcm_gmult_clmul)
#define _gcm_init_avx __PREFIX_MAC_ASM(BORINGSSL_PREFIX, gcm_init_avx)
#define _gcm_init_clmul __PREFIX_MAC_ASM(BORINGSSL_PREFIX, gcm_init_clmul)
#define _md5_block_asm_data_order __PREFIX_MAC_ASM(BORINGSSL_PREFIX, md5_block_asm_data_order)
#define _rsaz_1024_gather5_avx2 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, rsaz_1024_gather5_avx2)
#define _rsaz_1024_mul_avx2 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, rsaz_1024_mul_avx2)
#define _rsaz_1024_norm2red_avx2 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, rsaz_1024_norm2red_avx2)
#define _rsaz_1024_red2norm_avx2 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, rsaz_1024_red2norm_avx2)
#define _rsaz_1024_scatter5_avx2 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, rsaz_1024_scatter5_avx2)
#define _rsaz_1024_sqr_avx2 __PREFIX_MAC_ASM(BORINGSSL_PREFIX, rsaz_1024_sqr_avx2)
#define _rsaz_avx2_eligible __PREFIX_MAC_ASM(BORINGSSL_PREFIX, rsaz_avx2_eligible)
#define _sha1_block_data_order __PREFIX_MAC_ASM(BORINGSSL_PREFIX, sha1_block_data_order)
#define _sha256_block_data_order __PREFIX_MAC_ASM(BORINGSSL_PREFIX, sha256_block_data_order)
#define _sha512_block_data_order __PREFIX_MAC_ASM(BORINGSSL_PREFIX, sha512_block_data_order)
#define _vpaes_cbc_encrypt __PREFIX_MAC_ASM(BORINGSSL_PREFIX, vpaes_cbc_encrypt)
#define _vpaes_decrypt __PREFIX_MAC_ASM(BORINGSSL_PREFIX, vpaes_decrypt)
#define _vpaes_encrypt __PREFIX_MAC_ASM(BORINGSSL_PREFIX, vpaes_encrypt)
#define _vpaes_set_decrypt_key __PREFIX_MAC_ASM(BORINGSSL_PREFIX, vpaes_set_decrypt_key)
#define _vpaes_set_encrypt_key __PREFIX_MAC_ASM(BORINGSSL_PREFIX, vpaes_set_encrypt_key)
#define _OPENSSL_ia32cap_P __PREFIX_MAC_ASM(BORINGSSL_PREFIX, OPENSSL_ia32cap_P)

#endif // __APPLE__

#endif // BORINGSSL_PREFIX
#endif // BORINGSSL_HEADER_BORINGSSL_PREFIX_SYMBOLS_ASM_H