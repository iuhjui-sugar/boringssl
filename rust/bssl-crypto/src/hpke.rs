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

use alloc::vec::Vec;

/// KEM algorithms.
pub const KEM_X25519_HKDF_SHA256: u16 = bssl_sys::EVP_HPKE_DHKEM_X25519_HKDF_SHA256 as u16;

/// KDF algorithms.
pub const KDF_HKDF_SHA256: u16 = bssl_sys::EVP_HPKE_HKDF_SHA256 as u16;

/// AEAD algorithms.
pub const AEAD_AES_128_GCM: u16 = bssl_sys::EVP_HPKE_AES_128_GCM as u16;

/// Maximum length of the encapsulated key for all currently supported KEMs.
const MAX_ENC_LENGTH: usize = bssl_sys::EVP_HPKE_MAX_ENC_LENGTH as usize;

/// Error returned from unsuccessful HPKE operations.
#[derive(Debug)]
pub struct HpkeError;

/// HPKE parameters, including the key encapsulation mechanism (KEM), key derivation function (KDF),
/// and authenticated encryption with additional data (AEAD).
pub struct Params {
    kem: *const bssl_sys::EVP_HPKE_KEM,
    kdf: *const bssl_sys::EVP_HPKE_KDF,
    aead: *const bssl_sys::EVP_HPKE_AEAD,
}

impl Params {
    /// New Params from KEM, KDF, and AEAD identifiers, such as bssl_sys::EVP_HPKE_AES_128_GCM.
    pub fn new(kem: u16, kdf: u16, aead: u16) -> Result<Self, HpkeError> {
        if kem != KEM_X25519_HKDF_SHA256 || kdf != KDF_HKDF_SHA256 || aead != AEAD_AES_128_GCM {
            return Err(HpkeError);
        }
        // Safety: EVP_hpke_x25519_hkdf_sha256, EVP_hpke_hkdf_sha256, and EVP_hpke_aes_128_gcm
        // initialize structs containing constants and cannot return an error.
        unsafe {
            Ok(Self {
                kem: bssl_sys::EVP_hpke_x25519_hkdf_sha256() as *const bssl_sys::EVP_HPKE_KEM,
                kdf: bssl_sys::EVP_hpke_hkdf_sha256() as *const bssl_sys::EVP_HPKE_KDF,
                aead: bssl_sys::EVP_hpke_aes_128_gcm() as *const bssl_sys::EVP_HPKE_AEAD,
            })
        }
    }
}

/// HPKE recipient context.
pub struct RecipientContext {
    ctx: *mut bssl_sys::EVP_HPKE_CTX,
}

/// HPKE sender context.
pub struct SenderContext {
    ctx: RecipientContext,
    encapsulated_key: Vec<u8>,
}

impl SenderContext {
    /// New SenderContext.
    pub fn new(params: &Params, recipient_pub_key: &[u8], info: &[u8]) -> Result<Self, HpkeError> {
        unimplemented!();
    }

    /// Seal.
    pub fn seal(&self, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, HpkeError> {
        self.ctx.seal(pt, aad)
    }

    /// Encapsulated key.
    pub fn encapsulated_key(&self) -> &Vec<u8> {
        &self.encapsulated_key
    }
}

impl RecipientContext {
    /// New RecipientContext.
    pub fn new(
        params: &Params,
        recipient_priv_key: &[u8],
        encapsulated_key: &[u8],
        info: &[u8],
    ) -> Result<Self, HpkeError> {
        unimplemented!();
    }

    /// Seal.
    pub fn seal(&self, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, HpkeError> {
        unimplemented!();
    }

    /// Open.
    pub fn open(&self, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, HpkeError> {
        unimplemented!();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    struct TestVector {
        kem_id: u16,
        kdf_id: u16,
        aead_id: u16,
    }

    // https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1
    fn x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm() -> TestVector {
        TestVector {
            kem_id: 32,
            kdf_id: 1,
            aead_id: 1,
        }
    }

    #[test]
    fn disallowed_params_fail() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();

        assert!(!Params::new(0, vec.kdf_id, vec.aead_id).is_ok());
        assert!(!Params::new(vec.kem_id, 0, vec.aead_id).is_ok());
        assert!(!Params::new(vec.kem_id, vec.kdf_id, 0).is_ok());
        assert!(!Params::new(
            vec.kem_id,
            vec.kdf_id,
            bssl_sys::EVP_HPKE_AES_256_GCM as u16
        )
        .is_ok());
    }
}
