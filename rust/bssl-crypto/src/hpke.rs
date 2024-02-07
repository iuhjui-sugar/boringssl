/* Copyright (c) 2024, Google Inc.
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

//! Hybrid Public Key Encryption
//!
//! HPKE provides a variant of public key encryption of arbitrary-sized plaintexts
//! for a recipient public key. It works for any combination of an asymmetric key
//! encapsulation mechanism (KEM), key derivation function (KDF), and authenticated
//! encryption with additional data (AEAD) function.
//!
//! See RFC 9180 for more details.

use crate::{scoped, with_output_vec_fallible, FfiSlice};
use alloc::vec::Vec;

/// Supported KEM algorithms with values detailed in RFC 9180.
#[derive(PartialEq)]
#[allow(missing_docs)]
pub enum KemAlgorithm {
    X25519HkdfSha256 = 32,
}

/// Supported KDF algorithms with values detailed in RFC 9180.
#[derive(PartialEq)]
#[allow(missing_docs)]
pub enum KdfAlgorithm {
    HkdfSha256 = 1,
}

/// Supported AEAD algorithms with values detailed in RFC 9180.
#[derive(PartialEq)]
#[allow(missing_docs)]
pub enum AeadAlgorithm {
    Aes128Gcm = 1,
}

/// Maximum length of the encapsulated key for all currently supported KEMs.
const MAX_ENC_LENGTH: usize = bssl_sys::EVP_HPKE_MAX_ENC_LENGTH as usize;

/// HPKE parameters, including KEM, KDF, and AEAD.
pub struct Params {
    kem: *const bssl_sys::EVP_HPKE_KEM,
    kdf: *const bssl_sys::EVP_HPKE_KDF,
    aead: *const bssl_sys::EVP_HPKE_AEAD,
}

impl Params {
    /// New Params from KEM, KDF, and AEAD enums.
    pub fn new(kem: KemAlgorithm, kdf: KdfAlgorithm, aead: AeadAlgorithm) -> Option<Self> {
        if kem != KemAlgorithm::X25519HkdfSha256
            || kdf != KdfAlgorithm::HkdfSha256
            || aead != AeadAlgorithm::Aes128Gcm
        {
            return None;
        }
        // Safety: EVP_hpke_x25519_hkdf_sha256, EVP_hpke_hkdf_sha256, and EVP_hpke_aes_128_gcm
        // initialize structs containing constants and cannot return an error.
        unsafe {
            Some(Self {
                kem: bssl_sys::EVP_hpke_x25519_hkdf_sha256() as *const bssl_sys::EVP_HPKE_KEM,
                kdf: bssl_sys::EVP_hpke_hkdf_sha256() as *const bssl_sys::EVP_HPKE_KDF,
                aead: bssl_sys::EVP_hpke_aes_128_gcm() as *const bssl_sys::EVP_HPKE_AEAD,
            })
        }
    }

    /// New Params from KEM, KDF, and AEAD IDs as detailed in RFC 9180.
    pub fn new_with_u16(kem: u16, kdf: u16, aead: u16) -> Option<Self> {
        if kem != KemAlgorithm::X25519HkdfSha256 as u16
            || kdf != KdfAlgorithm::HkdfSha256 as u16
            || aead != AeadAlgorithm::Aes128Gcm as u16
        {
            return None;
        }
        // Safety: EVP_hpke_x25519_hkdf_sha256, EVP_hpke_hkdf_sha256, and EVP_hpke_aes_128_gcm
        // initialize structs containing constants and cannot return an error.
        unsafe {
            Some(Self {
                kem: bssl_sys::EVP_hpke_x25519_hkdf_sha256() as *const bssl_sys::EVP_HPKE_KEM,
                kdf: bssl_sys::EVP_hpke_hkdf_sha256() as *const bssl_sys::EVP_HPKE_KDF,
                aead: bssl_sys::EVP_hpke_aes_128_gcm() as *const bssl_sys::EVP_HPKE_AEAD,
            })
        }
    }
}

/// HPKE recipient context.
pub struct RecipientContext {
    ctx: scoped::EvpHpkeCtx,
}

/// HPKE sender context.
pub struct SenderContext {
    ctx: RecipientContext,
    encapsulated_key: Vec<u8>,
}

impl SenderContext {
    /// New SenderContext.
    pub fn new(params: &Params, recipient_pub_key: &[u8], info: &[u8]) -> Option<Self> {
        let mut ctx = scoped::EvpHpkeCtx::new();

        unsafe {
            with_output_vec_fallible(MAX_ENC_LENGTH, |enc_key_buf| {
                let mut enc_key_len = 0usize;
                // Safety: EVP_HPKE_CTX_setup_sender
                // - is called with context created from EVP_HPKE_CTX_new,
                // - is called with valid buffers with corresponding pointer and length, and
                // - returns 0 on error.
                let result = bssl_sys::EVP_HPKE_CTX_setup_sender(
                    ctx.as_mut_ffi_ptr(),
                    enc_key_buf,
                    &mut enc_key_len,
                    MAX_ENC_LENGTH,
                    params.kem,
                    params.kdf,
                    params.aead,
                    recipient_pub_key.as_ffi_ptr(),
                    recipient_pub_key.len(),
                    info.as_ffi_ptr(),
                    info.len(),
                );
                if result == 1 {
                    Some(enc_key_len)
                } else {
                    None
                }
            })
        }
        .map(|enc_key| Self {
            ctx: RecipientContext { ctx },
            encapsulated_key: enc_key,
        })
    }

    /// Seal.
    pub fn seal(&mut self, pt: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
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
    ) -> Option<Self> {
        let mut hpke_key = scoped::EvpHpkeKey::new();

        // Safety: EVP_HPKE_KEY_init returns 0 on error.
        let result = unsafe {
            bssl_sys::EVP_HPKE_KEY_init(
                hpke_key.as_mut_ffi_ptr(),
                params.kem,
                recipient_priv_key.as_ffi_ptr(),
                recipient_priv_key.len(),
            )
        };
        if result != 1 {
            return None;
        }

        let mut ctx = scoped::EvpHpkeCtx::new();

        // Safety: EVP_HPKE_CTX_setup_recipient
        // - is called with context created from EVP_HPKE_CTX_new,
        // - is called with HPKE key created from EVP_HPKE_KEY_init,
        // - is called with valid buffers with corresponding pointer and length, and
        // - returns 0 on error.
        let result = unsafe {
            bssl_sys::EVP_HPKE_CTX_setup_recipient(
                ctx.as_mut_ffi_ptr(),
                hpke_key.as_ffi_ptr(),
                params.kdf,
                params.aead,
                encapsulated_key.as_ffi_ptr(),
                encapsulated_key.len(),
                info.as_ffi_ptr(),
                info.len(),
            )
        };
        if result == 1 {
            Some(Self { ctx })
        } else {
            None
        }
    }

    /// Seal.
    pub fn seal(&mut self, pt: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        // Safety: EVP_HPKE_CTX_max_overhead panics if ctx is not set up as a sender.
        let max_out_len =
            pt.len() + unsafe { bssl_sys::EVP_HPKE_CTX_max_overhead(self.ctx.as_mut_ffi_ptr()) };

        unsafe {
            with_output_vec_fallible(max_out_len, |out_buf| {
                let mut out_len = 0usize;
                // Safety: EVP_HPKE_CTX_seal
                // - is called with context created from EVP_HPKE_CTX_new and
                // - is called with valid buffers with corresponding pointer and length.
                let result = bssl_sys::EVP_HPKE_CTX_seal(
                    self.ctx.as_mut_ffi_ptr(),
                    out_buf,
                    &mut out_len,
                    max_out_len,
                    pt.as_ffi_ptr(),
                    pt.len(),
                    aad.as_ffi_ptr(),
                    aad.len(),
                );
                if result == 1 {
                    Some(out_len)
                } else {
                    None
                }
            })
        }
    }

    /// Open.
    pub fn open(&mut self, ct: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        let max_out_len = ct.len();

        unsafe {
            with_output_vec_fallible(max_out_len, |out_buf| {
                let mut out_len = 0usize;
                // Safety: EVP_HPKE_CTX_open
                // - is called with context created from EVP_HPKE_CTX_new and
                // - is called with valid buffers with corresponding pointer and length.
                let result = bssl_sys::EVP_HPKE_CTX_open(
                    self.ctx.as_mut_ffi_ptr(),
                    out_buf,
                    &mut out_len,
                    max_out_len,
                    ct.as_ffi_ptr(),
                    ct.len(),
                    aad.as_ffi_ptr(),
                    aad.len(),
                );
                if result == 1 {
                    Some(out_len)
                } else {
                    None
                }
            })
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_helpers::decode_hex;

    struct TestVector {
        kem_id: u16,
        kdf_id: u16,
        aead_id: u16,
        info: [u8; 20],
        seed_for_testing: [u8; 32],   // skEm
        recipient_pub_key: [u8; 32],  // pkRm
        recipient_priv_key: [u8; 32], // skRm
        encapsulated_key: [u8; 32],   // enc
        plaintext: [u8; 29],          // pt
        associated_data: [u8; 7],     // aad
        ciphertext: [u8; 45],         // ct
    }

    // https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1
    fn x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm() -> TestVector {
        TestVector {
            kem_id: 32,
            kdf_id: 1,
            aead_id: 1,
            info: decode_hex("4f6465206f6e2061204772656369616e2055726e"),
            seed_for_testing: decode_hex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"),
            recipient_pub_key: decode_hex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"),
            recipient_priv_key: decode_hex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"),
            encapsulated_key: decode_hex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"),
            plaintext: decode_hex("4265617574792069732074727574682c20747275746820626561757479"),
            associated_data: decode_hex("436f756e742d30"),
            ciphertext: decode_hex("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"),
        }
    }

    #[test]
    fn seal_and_open() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();
        let params = Params::new_with_u16(vec.kem_id, vec.kdf_id, vec.aead_id).unwrap();

        let mut sender_ctx =
            SenderContext::new(&params, &vec.recipient_pub_key, &vec.info).unwrap();

        let recipient_ctx = RecipientContext::new(
            &params,
            &vec.recipient_priv_key,
            &sender_ctx.encapsulated_key(),
            &vec.info,
        );
        let mut recipient_ctx = recipient_ctx.unwrap();

        let pt = b"plaintext";
        let ad = b"associated_data";
        let mut prev_ct: Vec<u8> = Vec::new();
        for _ in 0..10 {
            let ct = sender_ctx.seal(pt, ad).unwrap();
            assert_ne!(ct, prev_ct);
            prev_ct = ct.clone();

            let got_pt = recipient_ctx.open(&ct, ad).unwrap();
            assert_eq!(got_pt, pt);
        }
    }

    fn new_sender_context_for_testing(
        params: &Params,
        recipient_pub_key: &[u8],
        info: &[u8],
        seed_for_testing: &[u8],
    ) -> Option<SenderContext> {
        let mut ctx = scoped::EvpHpkeCtx::new();

        unsafe {
            with_output_vec_fallible(MAX_ENC_LENGTH, |enc_key_buf| {
                let mut enc_key_len = 0usize;
                // Safety: EVP_HPKE_CTX_setup_sender_with_seed_for_testing
                // - is called with context created from EVP_HPKE_CTX_new,
                // - is called with valid buffers with corresponding pointer and length, and
                // - returns 0 on error.
                let result = bssl_sys::EVP_HPKE_CTX_setup_sender_with_seed_for_testing(
                    ctx.as_mut_ffi_ptr(),
                    enc_key_buf,
                    &mut enc_key_len,
                    MAX_ENC_LENGTH,
                    params.kem,
                    params.kdf,
                    params.aead,
                    recipient_pub_key.as_ffi_ptr(),
                    recipient_pub_key.len(),
                    info.as_ffi_ptr(),
                    info.len(),
                    seed_for_testing.as_ffi_ptr(),
                    seed_for_testing.len(),
                );
                if result == 1 {
                    Some(enc_key_len)
                } else {
                    None
                }
            })
        }
        .map(|enc_key| SenderContext {
            ctx: RecipientContext { ctx },
            encapsulated_key: enc_key,
        })
    }

    #[test]
    fn seal_with_vector() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();
        let params = Params::new_with_u16(vec.kem_id, vec.kdf_id, vec.aead_id).unwrap();

        let mut ctx = new_sender_context_for_testing(
            &params,
            &vec.recipient_pub_key,
            &vec.info,
            &vec.seed_for_testing,
        )
        .unwrap();

        assert_eq!(ctx.encapsulated_key, vec.encapsulated_key.to_vec());

        let ciphertext = ctx.seal(&vec.plaintext, &vec.associated_data).unwrap();
        assert_eq!(ciphertext, vec.ciphertext.to_vec());
    }

    #[test]
    fn open_with_vector() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();
        let params = Params::new_with_u16(vec.kem_id, vec.kdf_id, vec.aead_id).unwrap();

        let mut ctx = RecipientContext::new(
            &params,
            &vec.recipient_priv_key,
            &vec.encapsulated_key,
            &vec.info,
        )
        .unwrap();

        let plaintext = ctx.open(&vec.ciphertext, &vec.associated_data).unwrap();
        assert_eq!(plaintext, vec.plaintext.to_vec());
    }

    #[test]
    fn params_new() {
        assert!(Params::new(
            KemAlgorithm::X25519HkdfSha256,
            KdfAlgorithm::HkdfSha256,
            AeadAlgorithm::Aes128Gcm
        )
        .is_some());
    }

    #[test]
    fn params_new_with_u16() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();
        assert!(Params::new_with_u16(vec.kem_id, vec.kdf_id, vec.aead_id).is_some());
    }

    #[test]
    fn disallowed_params_fail() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();

        assert!(Params::new_with_u16(0, vec.kdf_id, vec.aead_id).is_none());
        assert!(Params::new_with_u16(vec.kem_id, 0, vec.aead_id).is_none());
        assert!(Params::new_with_u16(vec.kem_id, vec.kdf_id, 0).is_none());
        assert!(Params::new_with_u16(
            vec.kem_id,
            vec.kdf_id,
            bssl_sys::EVP_HPKE_AES_256_GCM as u16
        )
        .is_none());
    }

    #[test]
    fn bad_recipient_pub_key_fails() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();
        let params = Params::new_with_u16(vec.kem_id, vec.kdf_id, vec.aead_id).unwrap();

        assert!(SenderContext::new(&params, b"", &vec.info).is_none());
    }

    #[test]
    fn bad_recipient_priv_key_fails() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();
        let params = Params::new_with_u16(vec.kem_id, vec.kdf_id, vec.aead_id).unwrap();

        assert!(RecipientContext::new(&params, b"", &vec.encapsulated_key, &vec.info).is_none());
    }
}
