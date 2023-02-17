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
pub const BLOCK_SIZE: usize = bssl_sys::AES_BLOCK_SIZE as usize;

/// A single AES block.
pub type AesBlock = [u8; BLOCK_SIZE];

/// Aes implementation used for encrypting/decrypting a single `AesBlock` at a time
pub struct Aes;

/// An appropriately sized key for AES-128 operations. Can be constructed from a byte array and used
/// to create an encryption or decryption key
pub struct Aes128Key(AesKeyImpl<16>);

/// An appropriately sized key for AES-256 operations. Can be constructed from a byte array and used
/// to create an encryption or decryption key
pub struct Aes256Key(AesKeyImpl<32>);

/// An initialized key which can be used for encrypting
pub struct AesEncryptKey(bssl_sys::AES_KEY);

/// An initialized key which can be used for decrypting
pub struct AesDecryptKey(bssl_sys::AES_KEY);

impl Aes {
    /// Encrypt `block` in place.
    pub fn encrypt(key: &AesEncryptKey, block: &mut AesBlock) {
        let input = block.clone();
        // Safety:
        // - AesBlock is always a valid size and key is guaranteed to already be initialized
        unsafe { bssl_sys::AES_encrypt(input.as_ptr(), block.as_mut_ptr(), &key.0) }
    }

    /// Decrypt `block` in place.
    pub fn decrypt(key: &AesDecryptKey, block: &mut AesBlock) {
        let input = block.clone();
        // Safety:
        // - AesBlock is always a valid size and key is guaranteed to already be initialized
        unsafe { bssl_sys::AES_decrypt(input.as_ptr(), block.as_mut_ptr(), &key.0) }
    }
}

impl Aes128Key {
    /// Initializes a new `AesEncryptKey` from an `Aes128Key`, consuming self so it can't be re-used
    pub fn new_encrypt_key(self) -> AesEncryptKey {
        AesKeyImpl::new_encrypt_key(self.0)
    }

    /// Initializes a new `AesDecryptKey` from an `Aes128Key`, consuming self so it can't be re-used
    pub fn new_decrypt_key(self) -> AesDecryptKey {
        AesKeyImpl::new_decrypt_key(self.0)
    }

    /// Returns the key material as a slice
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns the key material as an array
    pub fn as_array(&self) -> [u8; 16] {
        self.0.as_array()
    }
}

impl From<[u8; 16]> for Aes128Key {
    fn from(value: [u8; 16]) -> Self {
        Self(AesKeyImpl::from(value))
    }
}

impl Aes256Key {
    /// Initializes a new `AesEncryptKey` from an `Aes256Key`, consuming self so it can't be re-used
    pub fn new_encrypt_key(self) -> AesEncryptKey {
        AesKeyImpl::new_encrypt_key(self.0)
    }

    /// Initializes a new `AesDecryptKey` from an `Aes256Key`, consuming self so it can't be re-used
    pub fn new_decrypt_key(self) -> AesDecryptKey {
        AesKeyImpl::new_decrypt_key(self.0)
    }

    /// Returns the key material as a slice
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns the key material as an array
    pub fn as_array(&self) -> [u8; 32] {
        self.0.as_array()
    }
}

impl From<[u8; 32]> for Aes256Key {
    fn from(value: [u8; 32]) -> Self {
        Self(AesKeyImpl::from(value))
    }
}

/// private generic implementation of an AesKey, which wraps a `[u8; N]` array of bytes. This should
/// only be exposed publicly by types with a correct key length, e.g. `[u8; 16]` for AES-128.
#[derive(Clone)]
struct AesKeyImpl<const N: usize>([u8; N]);

impl<const N: usize> AesKeyImpl<N> {
    /// configures the aes key to encrypt returning a new `AesEncryptKey` and consuming self so it can't be re-used
    fn new_encrypt_key(self) -> AesEncryptKey {
        let mut enc_key_uninit = core::mem::MaybeUninit::uninit();

        // Safety:
        // - key is guaranteed to point to bits/8 bytes determined by the len() * 8 used below
        // - bits is always a valid AES key size, as defined by the AesKey structs
        unsafe {
            bssl_sys::AES_set_encrypt_key(
                self.0.as_ptr(),
                self.0.len() as libc::c_uint * 8,
                enc_key_uninit.as_mut_ptr(),
            )
        }
        .eq(&0)
        .then_some(())
        .expect("will never be hit since input key is always a valid AES key size");

        // Safety:
        // - Since we have checked above that initialization succeeded, this will never be UB
        let enc_key = unsafe { enc_key_uninit.assume_init() };

        AesEncryptKey(enc_key)
    }

    /// configures the aes key to decrypt returning a new `AesDecryptKey` and consuming self so it can't be re-used
    fn new_decrypt_key(self) -> AesDecryptKey {
        let mut dec_key_uninit = core::mem::MaybeUninit::uninit();

        // Safety:
        // - key is guaranteed to point to bits/8 bytes determined by the len() * 8 used below
        // - bits is always a valid AES key size, as defined by the AesKey structs
        unsafe {
            bssl_sys::AES_set_decrypt_key(
                self.0.as_ptr(),
                self.0.len() as libc::c_uint * 8,
                dec_key_uninit.as_mut_ptr(),
            )
        }
        .eq(&0)
        .then_some(())
        .expect("will never be hit since input key is always a valid AES key size");

        // Safety:
        // - Since we have checked above that initialization succeeded, this will never be UB
        let dec_key = unsafe { dec_key_uninit.assume_init() };

        AesDecryptKey(dec_key)
    }

    /// initializes a key from an array of bytes
    fn from(arr: [u8; N]) -> Self {
        Self(arr)
    }

    /// Returns the key material as a slice
    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns the key material as an array
    fn as_array(&self) -> [u8; N] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::aes::{Aes, Aes128Key, Aes256Key};
    use hex_literal::hex;

    // test data from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf F.1.1
    #[test]
    fn aes_128_test_encrypt() {
        let key = Aes128Key::from(hex!("2b7e151628aed2a6abf7158809cf4f3c")).new_encrypt_key();
        let mut block = [0_u8; 16];

        block.copy_from_slice(&hex!("6bc1bee22e409f96e93d7e117393172a"));
        Aes::encrypt(&key, &mut block);
        assert_eq!(hex!("3ad77bb40d7a3660a89ecaf32466ef97"), block);

        block.copy_from_slice(&hex!("ae2d8a571e03ac9c9eb76fac45af8e51"));
        Aes::encrypt(&key, &mut block);
        assert_eq!(hex!("f5d3d58503b9699de785895a96fdbaaf"), block);

        block.copy_from_slice(&hex!("30c81c46a35ce411e5fbc1191a0a52ef"));
        Aes::encrypt(&key, &mut block);
        assert_eq!(hex!("43b1cd7f598ece23881b00e3ed030688"), block);

        block.copy_from_slice(&hex!("f69f2445df4f9b17ad2b417be66c3710"));
        Aes::encrypt(&key, &mut block);
        assert_eq!(hex!("7b0c785e27e8ad3f8223207104725dd4"), block);
    }

    // test data from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf F.1.2
    #[test]
    fn aes_128_test_decrypt() {
        let key = Aes128Key::from(hex!("2b7e151628aed2a6abf7158809cf4f3c")).new_decrypt_key();
        let mut block = [0_u8; 16];

        block.copy_from_slice(&hex!("3ad77bb40d7a3660a89ecaf32466ef97"));
        Aes::decrypt(&key, &mut block);
        assert_eq!(hex!("6bc1bee22e409f96e93d7e117393172a"), block);

        block.copy_from_slice(&hex!("f5d3d58503b9699de785895a96fdbaaf"));
        Aes::decrypt(&key, &mut block);
        assert_eq!(hex!("ae2d8a571e03ac9c9eb76fac45af8e51"), block);

        block.copy_from_slice(&hex!("43b1cd7f598ece23881b00e3ed030688"));
        Aes::decrypt(&key, &mut block);
        assert_eq!(hex!("30c81c46a35ce411e5fbc1191a0a52ef"), block);

        block.copy_from_slice(&hex!("7b0c785e27e8ad3f8223207104725dd4"));
        Aes::decrypt(&key, &mut block);
        assert_eq!(hex!("f69f2445df4f9b17ad2b417be66c3710"), block);
    }

    // test data from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf F.1.5
    #[test]
    pub fn aes_256_test_encrypt() {
        let key = Aes256Key::from(hex!(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        ))
        .new_encrypt_key();
        let mut block: [u8; 16];

        block = hex!("6bc1bee22e409f96e93d7e117393172a");
        Aes::encrypt(&key, &mut block);
        assert_eq!(hex!("f3eed1bdb5d2a03c064b5a7e3db181f8"), block);

        block = hex!("ae2d8a571e03ac9c9eb76fac45af8e51");
        Aes::encrypt(&key, &mut block);
        assert_eq!(hex!("591ccb10d410ed26dc5ba74a31362870"), block);

        block = hex!("30c81c46a35ce411e5fbc1191a0a52ef");
        Aes::encrypt(&key, &mut block);
        assert_eq!(hex!("b6ed21b99ca6f4f9f153e7b1beafed1d"), block);

        block = hex!("f69f2445df4f9b17ad2b417be66c3710");
        Aes::encrypt(&key, &mut block);
        assert_eq!(hex!("23304b7a39f9f3ff067d8d8f9e24ecc7"), block);
    }

    // test data from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf F.1.6
    #[test]
    fn aes_256_test_decrypt() {
        let key = Aes256Key::from(hex!(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        ))
        .new_decrypt_key();
        let mut block: [u8; 16];

        block = hex!("f3eed1bdb5d2a03c064b5a7e3db181f8");
        Aes::decrypt(&key, &mut block);
        assert_eq!(hex!("6bc1bee22e409f96e93d7e117393172a"), block);

        block = hex!("591ccb10d410ed26dc5ba74a31362870");
        Aes::decrypt(&key, &mut block);
        assert_eq!(hex!("ae2d8a571e03ac9c9eb76fac45af8e51"), block);

        block = hex!("b6ed21b99ca6f4f9f153e7b1beafed1d");
        Aes::decrypt(&key, &mut block);
        assert_eq!(hex!("30c81c46a35ce411e5fbc1191a0a52ef"), block);

        block = hex!("23304b7a39f9f3ff067d8d8f9e24ecc7");
        Aes::decrypt(&key, &mut block);
        assert_eq!(hex!("f69f2445df4f9b17ad2b417be66c3710"), block);
    }
}
