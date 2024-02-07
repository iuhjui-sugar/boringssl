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
//! encryption with additional data (AEAD) encryption function.
//!
//! See RFC 9180 for more details.

use crate::{CSlice, CSliceMut};
use alloc::vec;
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

/// HPKE parameters, including KEM, KDF, and AEAD.
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
        let mut enc_key = vec![0; MAX_ENC_LENGTH];
        let mut enc_key_cslice = CSliceMut::from(enc_key.as_mut_slice());
        let mut enc_key_len = 0usize;

        let recipient_pub_key_cslice = CSlice::from(recipient_pub_key);
        let info_cslice = CSlice::from(info);

        // Safety: EVP_HPKE_CTX_new returns null on error.
        let ctx = unsafe { bssl_sys::EVP_HPKE_CTX_new() };
        if ctx.is_null() {
            return Err(HpkeError);
        }

        // Safety: EVP_HPKE_CTX_setup_sender
        // - is called with context created from EVP_HPKE_CTX_new,
        // - is called with valid buffers with corresponding pointer and length, and
        // - returns 0 on error.
        let result = unsafe {
            bssl_sys::EVP_HPKE_CTX_setup_sender(
                ctx,
                enc_key_cslice.as_mut_ptr(),
                &mut enc_key_len,
                enc_key_cslice.len(),
                params.kem,
                params.kdf,
                params.aead,
                recipient_pub_key_cslice.as_ptr(),
                recipient_pub_key_cslice.len(),
                info_cslice.as_ptr(),
                info_cslice.len(),
            )
        };
        if result == 1 {
            Ok(Self {
                ctx: RecipientContext { ctx },
                encapsulated_key: enc_key,
            })
        } else {
            Err(HpkeError)
        }
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
        // Safety: EVP_HPKE_KEY_new returns null on error.
        let hpke_key = unsafe { bssl_sys::EVP_HPKE_KEY_new() };
        if hpke_key.is_null() {
            return Err(HpkeError);
        }

        let recipient_priv_key_cslice = CSlice::from(recipient_priv_key);

        // Safety: EVP_HPKE_KEY_init returns 0 on error.
        let result = unsafe {
            bssl_sys::EVP_HPKE_KEY_init(
                hpke_key,
                params.kem,
                recipient_priv_key_cslice.as_ptr(),
                recipient_priv_key_cslice.len(),
            )
        };
        if result != 1 {
            return Err(HpkeError);
        }

        // Safety: EVP_HPKE_CTX_new returns null on error.
        let ctx = unsafe { bssl_sys::EVP_HPKE_CTX_new() };
        if ctx.is_null() {
            return Err(HpkeError);
        }

        let encapsulated_key_cslice = CSlice::from(encapsulated_key);
        let info_cslice = CSlice::from(info);

        // Safety: EVP_HPKE_CTX_setup_recipient
        // - is called with context created from EVP_HPKE_CTX_new,
        // - is called with HPKE key created from EVP_HPKE_KEY_init,
        // - is called with valid buffers with corresponding pointer and length, and
        // - returns 0 on error.
        let result = unsafe {
            bssl_sys::EVP_HPKE_CTX_setup_recipient(
                ctx,
                hpke_key,
                params.kdf,
                params.aead,
                encapsulated_key_cslice.as_ptr(),
                encapsulated_key_cslice.len(),
                info_cslice.as_ptr(),
                info_cslice.len(),
            )
        };
        if result == 1 {
            Ok(Self { ctx })
        } else {
            Err(HpkeError)
        }
    }

    /// Seal.
    pub fn seal(&self, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, HpkeError> {
        // Safety: EVP_HPKE_CTX_max_overhead panics if ctx is not set up as a sender.
        let mut out = vec![0; pt.len() + unsafe { bssl_sys::EVP_HPKE_CTX_max_overhead(self.ctx) }];
        let mut out_cslice = CSliceMut::from(out.as_mut_slice());
        let mut out_len = 0usize;

        let pt_cslice = CSlice::from(pt);
        let aad_cslice = CSlice::from(aad);

        // Safety: EVP_HPKE_CTX_seal
        // - is called with context created from EVP_HPKE_CTX_new and
        // - is called with valid buffers with corresponding pointer and length.
        let result = unsafe {
            bssl_sys::EVP_HPKE_CTX_seal(
                self.ctx,
                out_cslice.as_mut_ptr(),
                &mut out_len,
                out_cslice.len(),
                pt_cslice.as_ptr(),
                pt_cslice.len(),
                aad_cslice.as_ptr(),
                aad_cslice.len(),
            )
        };

        if result == 1 {
            if out_len < out.len() {
                out.truncate(out_len)
            }
            Ok(out)
        } else {
            Err(HpkeError)
        }
    }

    /// Open.
    pub fn open(&self, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let mut out = vec![0; ct.len()];
        let mut out_cslice = CSliceMut::from(out.as_mut_slice());
        let aad_cslice = CSlice::from(aad);
        let ct_cslice = CSlice::from(ct);
        let mut out_len = 0usize;

        // Safety: EVP_HPKE_CTX_open
        // - is called with context created from EVP_HPKE_CTX_new and
        // - is called with valid buffers with corresponding pointer and length.
        let result = unsafe {
            bssl_sys::EVP_HPKE_CTX_open(
                self.ctx,
                out_cslice.as_mut_ptr(),
                &mut out_len,
                out_cslice.len(),
                ct_cslice.as_ptr(),
                ct_cslice.len(),
                aad_cslice.as_ptr(),
                aad_cslice.len(),
            )
        };

        if result == 1 {
            if out_len < out.len() {
                out.truncate(out_len)
            }
            Ok(out)
        } else {
            Err(HpkeError)
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
        let params = Params::new(vec.kem_id, vec.kdf_id, vec.aead_id);
        assert!(params.is_ok());
        let params = params.unwrap();

        let sender_ctx = SenderContext::new(&params, &vec.recipient_pub_key, &vec.info);
        assert!(sender_ctx.is_ok());
        let sender_ctx = sender_ctx.unwrap();

        let recipient_ctx = RecipientContext::new(
            &params,
            &vec.recipient_priv_key,
            &sender_ctx.encapsulated_key(),
            &vec.info,
        );
        assert!(recipient_ctx.is_ok());
        let recipient_ctx = recipient_ctx.unwrap();

        let pt = b"plaintext";
        let ad = b"associated_data";
        let mut prev_ct: Vec<u8> = Vec::new();
        for _ in 0..10 {
            let ct = sender_ctx.seal(pt, ad);
            assert!(ct.is_ok());
            let ct = ct.unwrap();
            assert_ne!(ct, prev_ct);
            prev_ct = ct.clone();

            let got_pt = recipient_ctx.open(&ct, ad);
            assert!(got_pt.is_ok());
            assert_eq!(got_pt.unwrap(), pt);
        }
    }

    fn new_sender_context_for_testing(
        params: &Params,
        recipient_pub_key: &[u8],
        info: &[u8],
        seed_for_testing: &[u8],
    ) -> Result<SenderContext, HpkeError> {
        let mut enc_key = vec![0; MAX_ENC_LENGTH];
        let mut enc_key_cslice = CSliceMut::from(enc_key.as_mut_slice());
        let mut enc_key_len = 0usize;

        let recipient_pub_key_cslice = CSlice::from(recipient_pub_key);
        let info_cslice = CSlice::from(info);
        let seed_for_testing_cslice = CSlice::from(seed_for_testing);

        // Safety: EVP_HPKE_CTX_new returns null on error.
        let ctx = unsafe { bssl_sys::EVP_HPKE_CTX_new() };
        if ctx.is_null() {
            return Err(HpkeError);
        }

        // Safety: EVP_HPKE_CTX_setup_sender_with_seed_for_testing
        // - is called with context created from EVP_HPKE_CTX_new,
        // - is called with valid buffers with corresponding pointer and length, and
        // - returns 0 on error.
        let result = unsafe {
            bssl_sys::EVP_HPKE_CTX_setup_sender_with_seed_for_testing(
                ctx,
                enc_key_cslice.as_mut_ptr(),
                &mut enc_key_len,
                enc_key_cslice.len(),
                params.kem,
                params.kdf,
                params.aead,
                recipient_pub_key_cslice.as_ptr(),
                recipient_pub_key_cslice.len(),
                info_cslice.as_ptr(),
                info_cslice.len(),
                seed_for_testing_cslice.as_ptr(),
                seed_for_testing_cslice.len(),
            )
        };
        if result == 1 {
            Ok(SenderContext {
                ctx: RecipientContext { ctx },
                encapsulated_key: enc_key,
            })
        } else {
            Err(HpkeError)
        }
    }

    #[test]
    fn seal_with_vector() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();
        let params = Params::new(vec.kem_id, vec.kdf_id, vec.aead_id);
        assert!(params.is_ok());

        let ctx = new_sender_context_for_testing(
            &params.unwrap(),
            &vec.recipient_pub_key,
            &vec.info,
            &vec.seed_for_testing,
        );
        assert!(ctx.is_ok());
        let ctx = ctx.unwrap();

        assert_eq!(ctx.encapsulated_key, vec.encapsulated_key.to_vec());

        let ciphertext = ctx.seal(&vec.plaintext, &vec.associated_data);
        assert!(ciphertext.is_ok());
        assert_eq!(ciphertext.unwrap(), vec.ciphertext.to_vec());
    }

    #[test]
    fn open_with_vector() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();
        let params = Params::new(vec.kem_id, vec.kdf_id, vec.aead_id);
        assert!(params.is_ok());

        let ctx = RecipientContext::new(
            &params.unwrap(),
            &vec.recipient_priv_key,
            &vec.encapsulated_key,
            &vec.info,
        );
        assert!(ctx.is_ok());

        let plaintext = ctx.unwrap().open(&vec.ciphertext, &vec.associated_data);
        assert!(plaintext.is_ok());
        assert_eq!(plaintext.unwrap(), vec.plaintext.to_vec());
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

    #[test]
    fn bad_recipient_pub_key_fails() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();
        let params = Params::new(vec.kem_id, vec.kdf_id, vec.aead_id);
        assert!(params.is_ok());

        assert!(!SenderContext::new(&params.unwrap(), b"", &vec.info).is_ok());
    }

    #[test]
    fn bad_recipient_priv_key_fails() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();
        let params = Params::new(vec.kem_id, vec.kdf_id, vec.aead_id);
        assert!(params.is_ok());

        assert!(
            !RecipientContext::new(&params.unwrap(), b"", &vec.encapsulated_key, &vec.info).is_ok()
        );
    }
}

