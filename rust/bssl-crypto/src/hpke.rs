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
use crate::{CSlice, CSliceMut};

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
    kem: *mut bssl_sys::EVP_HPKE_KEM,
    kdf: *mut bssl_sys::EVP_HPKE_KDF,
    aead: *mut bssl_sys::EVP_HPKE_AEAD,
}

impl Params {
    /// New parameters.
    pub fn new(kem: u16, kdf: u16, aead: u16) -> Result<Self, HpkeError> {
        if kem != KEM_X25519_HKDF_SHA256 || kdf != KDF_HKDF_SHA256 || aead != AEAD_AES_128_GCM {
            return Err(HpkeError)
        }
        Ok(Self {
            kem: bssl_sys::EVP_hpke_x25519_hkdf_sha256 as *mut bssl_sys::EVP_HPKE_KEM,
            kdf: bssl_sys::EVP_hpke_hkdf_sha256 as *mut bssl_sys::EVP_HPKE_KDF,
            aead: bssl_sys::EVP_hpke_aes_128_gcm as *mut bssl_sys::EVP_HPKE_AEAD,
        })
    }
}

/// HPKE recipient context.
pub struct RecipientContext {
    ctx: *mut bssl_sys::EVP_HPKE_CTX,
}

/// HPKE sender context.
pub struct SenderContext {
    _ctx: *mut RecipientContext,
    _encapsulated_key: Vec<u8>,  // [u8; MAX_ENC_LENGTH],
}

impl SenderContext {
    /// New sender context.
    pub fn new(params: Params, peer_public_key: &[u8], info: &[u8]) -> Self {
        let mut enc_key = Vec::new();
        enc_key.resize(MAX_ENC_LENGTH, 0u8);
        let mut enc_key_cslice = CSliceMut::from(enc_key.as_mut_slice());
        let mut enc_key_len = 0usize;

        let peer_public_key_cslice = CSlice::from(peer_public_key);
        let info_cslice = CSlice::from(info);

        // Safety:
        // - EVP_HPKE_CTX_new panics if allocation fails
        let ctx = unsafe { bssl_sys::EVP_HPKE_CTX_new() };
        assert!(
            !ctx.is_null(),
            "result of bssl_sys::EVP_HPKE_CTX_new() was null"
        );

        // Safety:
        // - EVP_HPKE_CTX_setup_sender must be called with context created from EVP_HPKE_CTX_new.
        // - EVP_HPKE_CTX_setup_sender returns 0 on error, in which case we panic.
        let result = unsafe {
            bssl_sys::EVP_HPKE_CTX_setup_sender(
                ctx,
                enc_key_cslice.as_mut_ptr(),
                &mut enc_key_len,
                enc_key_cslice.len(),
                params.kem,
                params.kdf,
                params.aead,
                peer_public_key_cslice.as_ptr(),
                peer_public_key_cslice.len(),
                info_cslice.as_ptr(),
                info_cslice.len(),
            )
        };
        assert_eq!(result, 1, "bssl_sys::EVP_HPKE_CTX_setup_sender returned an error");

        let mut recipient_ctx = RecipientContext { ctx: ctx, };
        Self {
            _ctx: &mut recipient_ctx,
            _encapsulated_key: enc_key,
        }
    }
}

impl RecipientContext {
    /// New recipient context.
    pub fn new(_encapsulated_key: &[u8], _ctx_info: &[u8]) -> Self {
        unimplemented!();
    }

    /// Seal.
    pub fn seal(&self, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let mut out = Vec::new();
        out.resize(pt.len() + unsafe { bssl_sys::EVP_HPKE_CTX_max_overhead(self.ctx) }, 0u8);
        let mut out_cslice = CSliceMut::from(out.as_mut_slice());
        let mut out_len = 0usize;

        let pt_cslice = CSlice::from(pt);
        let aad_cslice = CSlice::from(aad);

        // Safety:
        // - The buffers are valid, with corresponding pointer and length.
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
        let mut out = Vec::new();
        out.resize(ct.len(), 0u8);

        let mut out_cslice = CSliceMut::from(out.as_mut_slice());
        let aad_cslice = CSlice::from(aad);
        let ct_cslice = CSlice::from(ct);
        let mut out_len = 0usize;

        // Safety:
        // - The buffers are valid, with corresponding pointer and length.
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

    #[test]
    fn seal() {
        let params = Params::new(KEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
        assert!(params.is_ok());
        // http://google3/third_party/tink/cc/hybrid/internal/hpke_test_util.cc;l=32;rcl=454709535
        let peer_pub_key: [u8; 32] = decode_hex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        let info: [u8; 20] = decode_hex("4f6465206f6e2061204772656369616e2055726e");
        SenderContext::new(params.unwrap(), &peer_pub_key, &info);
        assert_eq!(true, false);
    }
}
