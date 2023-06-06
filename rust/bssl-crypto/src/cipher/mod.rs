/* Copyright (c) 2023, Google Inc.
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
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

use crate::CSliceMut;
use bssl_sys::EVP_CIPHER;
use std::ffi::c_int;

/// BoringSSL implemented AES-CTR ciphers.
pub mod aes_ctr;

/// Error returned in the event of an unsuccessful cipher operation.
#[derive(Debug)]
pub struct CipherError;

/// Synchronous stream cipher trait.
pub trait StreamCipher<const K: usize, const I: usize> {
    /// Instantiate a new instance of a stream cipher from a `key` and `iv`.
    fn new(key: [u8; K], iv: [u8; I]) -> Self;

    /// Applies the cipher keystream to `buffer` in place, returning CipherError on an unsuccessful
    /// operation.
    fn apply_keystream(&mut self, buffer: &mut [u8]) -> Result<(), CipherError>;
}

enum CipherType {
    Aes128Ctr,
    Aes256Ctr,
}

impl CipherType {
    fn to_evp_cipher(&self) -> *const EVP_CIPHER {
        // Safety:
        // - There are no preconditions to the EVP_CIPHER primitive definitions
        unsafe {
            match self {
                CipherType::Aes128Ctr => bssl_sys::EVP_aes_128_ctr(),
                CipherType::Aes256Ctr => bssl_sys::EVP_aes_256_ctr(),
            }
        }
    }
}

// Internal cipher implementation which wraps EVP_CIPHER_*, where K is the size of the Key and I is
// the size of the IV. This must only be exposed publicly by types who ensure that K is the correct
// size for the given CipherType. This can be checked via bssl_sys::EVP_CIPHER_key_length.
//
// WARNING: This is not safe to re-use for the CBC mode of operation since it is applying the
// key stream in-place.
struct Cipher<const K: usize, const I: usize>(*mut bssl_sys::EVP_CIPHER_CTX);

impl<const K: usize, const I: usize> Cipher<K, I> {
    fn new(key: &[u8; K], iv: &[u8; I], cipher_type: CipherType) -> Self {
        // Safety:
        // - Panics on allocation failure.
        let ctx = unsafe { bssl_sys::EVP_CIPHER_CTX_new() };
        assert!(!ctx.is_null());

        // Safety:
        // - Key size and nonce size must be properly set by the higher level wrapper types.
        // - Panics on allocation failure.
        let result = unsafe {
            bssl_sys::EVP_EncryptInit_ex(
                ctx,
                cipher_type.to_evp_cipher(),
                std::ptr::null_mut(),
                key.as_ptr(),
                iv.as_ptr(),
            )
        };
        assert_eq!(result, 1);

        Self(ctx)
    }

    fn apply_keystream_in_place(&mut self, buffer: &mut [u8]) -> Result<(), CipherError> {
        let mut cslice_buf_mut = CSliceMut::from(buffer);
        let mut out_len = 0;

        //TODO: Would it be be better to instead make this infallible and panic if the length does
        // not fit into an int?
        let buff_len_int = c_int::try_from(cslice_buf_mut.len()).map_err(|_| CipherError)?;

        // Safety:
        // - The output buffer provided is always large enough for an in-place operation.
        let result = unsafe {
            bssl_sys::EVP_EncryptUpdate(
                self.0,
                cslice_buf_mut.as_mut_ptr(),
                &mut out_len,
                cslice_buf_mut.as_mut_ptr(),
                buff_len_int,
            )
        };
        if result == 1 {
            assert_eq!(out_len as usize, cslice_buf_mut.len());
            Ok(())
        } else {
            Err(CipherError)
        }
    }
}
