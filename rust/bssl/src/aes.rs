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

use std::marker::PhantomData;

/// Block size in bytes for AES (and XTS-AES)
pub const BLOCK_SIZE: usize = bssl_sys::AES_BLOCK_SIZE as usize;

/// A single AES block.
pub type AesBlock = [u8; BLOCK_SIZE];

/// Abstraction around AES to make plugging in different AES implementations easy. Where N is the size of the key
pub trait Aes<const N: usize> {
    /// The [AesKey] this cipher uses. See [Aes128Key] and [Aes256Key] for the common AES-128 and
    /// AES-256 cases.
    type Key: AesKey<N>;

    /// Build a `Self` from key material.
    fn new(key: &Self::Key) -> Self;

    /// Encrypt `block` in place.
    fn encrypt(&self, block: &mut AesBlock);

    /// Decrypt `block` in place.
    fn decrypt(&self, block: &mut AesBlock);
}

/// An appropriately sized `[u8; N]` array that the key can be constructed from, e.g. `[u8; 16]`
/// for AES-128.
pub trait AesKey<const N: usize> {
    /// Returns the key material as a slice
    fn as_slice(&self) -> &[u8];

    /// Returns the key material as an array
    fn as_array(&self) -> [u8; N];
}

/// An AES-128 key.
#[derive(Clone)]
pub struct Aes128Key([u8; 16]);

/// An AES-256 key.
#[derive(Clone)]
pub struct Aes256Key([u8; 32]);

/// AES-128 implementation
pub struct Aes128(AesImpl<16, Aes128Key>);

/// AES-256 implementation
pub struct Aes256(AesImpl<32, Aes256Key>);

impl Aes<16> for Aes128 {
    type Key = Aes128Key;

    fn new(key: &Self::Key) -> Self {
        Self(AesImpl::new(key))
    }

    fn encrypt(&self, block: &mut AesBlock) {
        self.0.encrypt(block)
    }

    fn decrypt(&self, block: &mut AesBlock) {
        self.0.decrypt(block)
    }
}

impl AesKey<16> for Aes128Key {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn as_array(&self) -> [u8; 16] {
        self.0
    }
}

impl From<[u8; 16]> for Aes128Key {
    fn from(arr: [u8; 16]) -> Self {
        Self(arr)
    }
}

impl Aes<32> for Aes256 {
    type Key = Aes256Key;

    fn new(key: &Self::Key) -> Self {
        Self(AesImpl::new(key))
    }

    fn encrypt(&self, block: &mut AesBlock) {
        self.0.encrypt(block)
    }

    fn decrypt(&self, block: &mut AesBlock) {
        self.0.decrypt(block)
    }
}

impl AesKey<32> for Aes256Key {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn as_array(&self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for Aes256Key {
    fn from(arr: [u8; 32]) -> Self {
        Self(arr)
    }
}

/// private generic implementation for Aes, for different key sizes, see Aes128 and Aes256
/// N is the size of the key and K is the AesKey implementation ie `Aes128Key`
struct AesImpl<const N: usize, K: AesKey<N>> {
    enc_key: bssl_sys::AES_KEY,
    dec_key: bssl_sys::AES_KEY,
    marker: PhantomData<K>,
}

impl<const N: usize, K: AesKey<N>> AesImpl<N, K> {
    fn new(key: &K) -> Self {
        let mut enc_key_uninit = core::mem::MaybeUninit::uninit();

        // Safety:
        // - key is guaranteed to point to bits/8 bytes determined by the len() * 8 used below
        // - bits is always a valid AES key size, as defined by the AesKey structs
        unsafe {
            bssl_sys::AES_set_encrypt_key(
                key.as_array().as_ptr(),
                key.as_array().len() as libc::c_uint * 8,
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
        // - key is guaranteed to point to bits/8 bytes determined by the len() * 8 used below
        // - bits is always a valid AES key size, as defined by the AesKey structs
        unsafe {
            bssl_sys::AES_set_decrypt_key(
                key.as_array().as_ptr(),
                key.as_array().len() as libc::c_uint * 8,
                dec_key_uninit.as_mut_ptr(),
            )
        }
        .eq(&0)
        .then_some(())
        .expect("will never be hit since input key is always a valid AES key size");

        // Safety:
        // - Since we have checked above that initialization succeeded, this will never be UB
        let dec_key = unsafe { dec_key_uninit.assume_init() };

        Self {
            enc_key,
            dec_key,
            marker: Default::default(),
        }
    }

    fn encrypt(&self, block: &mut AesBlock) {
        let input = block.clone();
        // Safety:
        // - AesBlock and tmp are always a valid size, enc_key is guaranteed to already be initialized
        unsafe { bssl_sys::AES_encrypt(input.as_ptr(), block.as_mut_ptr(), &self.enc_key) }
    }

    fn decrypt(&self, block: &mut AesBlock) {
        let input = block.clone();
        // Safety:
        // - AesBlock and tmp are always a valid size, dec_key is guaranteed to already be initialized
        unsafe { bssl_sys::AES_decrypt(input.as_ptr(), block.as_mut_ptr(), &self.dec_key) }
    }
}

#[cfg(test)]
mod tests {
    use crate::aes::{Aes, Aes128, Aes128Key, Aes256, Aes256Key};
    use hex_literal::hex;

    // test data from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf F.1.1
    #[test]
    fn aes_128_test_encrypt() {
        let key = Aes128Key::from(hex!("2b7e151628aed2a6abf7158809cf4f3c"));
        let mut block = [0_u8; 16];

        let aes = Aes128::new(&key);

        block.copy_from_slice(&hex!("6bc1bee22e409f96e93d7e117393172a"));
        aes.encrypt(&mut block);
        assert_eq!(hex!("3ad77bb40d7a3660a89ecaf32466ef97"), block);

        block.copy_from_slice(&hex!("ae2d8a571e03ac9c9eb76fac45af8e51"));
        aes.encrypt(&mut block);
        assert_eq!(hex!("f5d3d58503b9699de785895a96fdbaaf"), block);

        block.copy_from_slice(&hex!("30c81c46a35ce411e5fbc1191a0a52ef"));
        aes.encrypt(&mut block);
        assert_eq!(hex!("43b1cd7f598ece23881b00e3ed030688"), block);

        block.copy_from_slice(&hex!("f69f2445df4f9b17ad2b417be66c3710"));
        aes.encrypt(&mut block);
        assert_eq!(hex!("7b0c785e27e8ad3f8223207104725dd4"), block);
    }

    // test data from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf F.1.2
    #[test]
    fn aes_128_test_decrypt() {
        let key = Aes128Key::from(hex!("2b7e151628aed2a6abf7158809cf4f3c"));
        let mut block = [0_u8; 16];
        let aes = Aes128::new(&key);

        block.copy_from_slice(&hex!("3ad77bb40d7a3660a89ecaf32466ef97"));
        aes.decrypt(&mut block);
        assert_eq!(hex!("6bc1bee22e409f96e93d7e117393172a"), block);

        block.copy_from_slice(&hex!("f5d3d58503b9699de785895a96fdbaaf"));
        aes.decrypt(&mut block);
        assert_eq!(hex!("ae2d8a571e03ac9c9eb76fac45af8e51"), block);

        block.copy_from_slice(&hex!("43b1cd7f598ece23881b00e3ed030688"));
        aes.decrypt(&mut block);
        assert_eq!(hex!("30c81c46a35ce411e5fbc1191a0a52ef"), block);

        block.copy_from_slice(&hex!("7b0c785e27e8ad3f8223207104725dd4"));
        aes.decrypt(&mut block);
        assert_eq!(hex!("f69f2445df4f9b17ad2b417be66c3710"), block);
    }

    // test data from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf F.1.5
    #[test]
    pub fn aes_256_test_encrypt() {
        let key = Aes256Key::from(hex!(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        ));
        let mut block: [u8; 16];
        let aes = Aes256::new(&key);

        block = hex!("6bc1bee22e409f96e93d7e117393172a");
        aes.encrypt(&mut block);
        assert_eq!(hex!("f3eed1bdb5d2a03c064b5a7e3db181f8"), block);

        block = hex!("ae2d8a571e03ac9c9eb76fac45af8e51");
        aes.encrypt(&mut block);
        assert_eq!(hex!("591ccb10d410ed26dc5ba74a31362870"), block);

        block = hex!("30c81c46a35ce411e5fbc1191a0a52ef");
        aes.encrypt(&mut block);
        assert_eq!(hex!("b6ed21b99ca6f4f9f153e7b1beafed1d"), block);

        block = hex!("f69f2445df4f9b17ad2b417be66c3710");
        aes.encrypt(&mut block);
        assert_eq!(hex!("23304b7a39f9f3ff067d8d8f9e24ecc7"), block);
    }

    // test data from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf F.1.6
    #[test]
    fn aes_256_test_decrypt() {
        let key = Aes256Key::from(hex!(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        ));
        let mut block: [u8; 16];
        let aes = Aes256::new(&key);

        block = hex!("f3eed1bdb5d2a03c064b5a7e3db181f8");
        aes.decrypt(&mut block);
        assert_eq!(hex!("6bc1bee22e409f96e93d7e117393172a"), block);

        block = hex!("591ccb10d410ed26dc5ba74a31362870");
        aes.decrypt(&mut block);
        assert_eq!(hex!("ae2d8a571e03ac9c9eb76fac45af8e51"), block);

        block = hex!("b6ed21b99ca6f4f9f153e7b1beafed1d");
        aes.decrypt(&mut block);
        assert_eq!(hex!("30c81c46a35ce411e5fbc1191a0a52ef"), block);

        block = hex!("23304b7a39f9f3ff067d8d8f9e24ecc7");
        aes.decrypt(&mut block);
        assert_eq!(hex!("f69f2445df4f9b17ad2b417be66c3710"), block);
    }
}
