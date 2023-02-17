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

/// Block size in bytes for AES (and XTS-AES)
pub const BLOCK_SIZE: i32 = bssl_sys::AES_BLOCK_SIZE;

/// A single AES block.
pub type AesBlock = [u8; BLOCK_SIZE as usize];

/// Abstraction around AES to make plugging in different AES implementations easy.
pub trait Aes {
    /// The [AesKey] this cipher uses. See [Aes128Key] and [Aes256Key] for the common AES-128 and
    /// AES-256 cases.
    type Key: AesKey;

    /// Build a `Self` from key material.
    fn new(key: &Self::Key) -> Self;

    /// Encrypt `block` in place.
    fn encrypt(&self, block: &mut AesBlock);

    /// Decrypt `block` in place.
    fn decrypt(&self, block: &mut AesBlock);
}

/// An appropriately sized `[u8; N]` array that the key can be constructed from, e.g. `[u8; 16]`
/// for AES-128.
pub trait AesKey {
    /// The byte array type the key can be represented with
    type Array;

    /// Key size in bytes -- must match the length of `Self::KeyBytes`.`
    ///
    /// Unfortunately `KeyBytes` can't reference this const in the type declaration, so it must be
    /// specified separately.
    const KEY_SIZE: usize;

    /// Returns the key material as a slice
    fn as_slice(&self) -> &[u8];

    /// Returns the key material as an array
    fn as_array(&self) -> &Self::Array;
}

///
pub struct Aes128 {
    enc_key: bssl_sys::AES_KEY,
    dec_key: bssl_sys::AES_KEY,
}

impl Aes for Aes128 {
    type Key = Aes128Key;

    fn new(key: &Self::Key) -> Self {
        let mut enc_key_uninit = core::mem::MaybeUninit::uninit();

        // Safety:
        // - TODO:
        unsafe {
            bssl_sys::AES_set_encrypt_key(
                key.0.as_ptr(),
                key.0.len() as libc::c_uint * 8,
                enc_key_uninit.as_mut_ptr(),
            )
        }
        .eq(&0)
        .then_some(())
        .expect("will never be hit since input key is always a valid AES key size");

        // Safety:
        // - Since we have checked above that initialization succeeded, this will never be UB
        let enc_key = unsafe { enc_key_uninit.assume_init() };

        let mut dec_key_uninit = core::mem::MaybeUninit::uninit();

        // Safety:
        // - TODO:
        unsafe {
            bssl_sys::AES_set_decrypt_key(
                key.0.as_ptr(),
                key.0.len() as libc::c_uint * 8,
                dec_key_uninit.as_mut_ptr(),
            )
        }
        .eq(&0)
        .then_some(())
        .expect("will never be hit since input key is always a valid AES key size");

        // Safety:
        // - Since we have checked above that initialization succeeded, this will never be UB
        let dec_key = unsafe { dec_key_uninit.assume_init() };

        Self { enc_key, dec_key }
    }

    fn encrypt(&self, block: &mut AesBlock) {
        let mut tmp = AesBlock::default();
        // Safety:
        // - TODO:
        unsafe { bssl_sys::AES_encrypt(block.as_ptr(), tmp.as_mut_ptr(), &self.enc_key) }

        // TODO: do without copying?
        block.copy_from_slice(&tmp);
    }

    fn decrypt(&self, block: &mut AesBlock) {
        let mut tmp = AesBlock::default();
        // Safety:
        // - TODO:
        unsafe { bssl_sys::AES_decrypt(block.as_ptr(), tmp.as_mut_ptr(), &self.dec_key) }

        // TODO: do without copying?
        block.copy_from_slice(&tmp);
    }
}

/// An AES-128 key.
#[derive(Clone)]
pub struct Aes128Key([u8; 16]);

/// An AES-256 key.
#[derive(Clone)]
pub struct Aes256Key([u8; 32]);

impl AesKey for Aes128Key {
    type Array = [u8; 16];
    const KEY_SIZE: usize = 16;

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn as_array(&self) -> &Self::Array {
        &self.0
    }
}

impl From<[u8; 16]> for Aes128Key {
    fn from(arr: [u8; 16]) -> Self {
        Self(arr)
    }
}

impl AesKey for Aes256Key {
    type Array = [u8; 32];
    const KEY_SIZE: usize = 32;

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn as_array(&self) -> &Self::Array {
        &self.0
    }
}

impl From<[u8; 32]> for Aes256Key {
    fn from(arr: [u8; 32]) -> Self {
        Self(arr)
    }
}
