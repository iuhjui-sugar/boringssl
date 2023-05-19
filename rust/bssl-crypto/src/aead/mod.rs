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
use crate::CSlice;
use bssl_sys::{EVP_AEAD, EVP_AEAD_CTX};

/// BoringSSL implemented AES-GCM-SIV operations.
pub mod aes_gcm_siv;

/// Error returned in the event of an unsuccessful AEAD operation.
#[derive(Debug)]
pub struct AeadError;

/// BoringSSL implemented AEAD operations where N is the size of the nonce.
pub trait Aead<const N: usize> {
    /// The size of the auth tag for the given AEAD implementation. This is the amount of bytes
    /// appended to the data when it is encrypted.
    const TAG_SIZE: usize;

    /// Encrypt the given buffer containing a plaintext message in-place. On success increases the
    /// buffer by `Self::TAG_SIZE` bytes and appends the auth tag to the end of `msg`.
    fn encrypt(&self, msg: &mut Vec<u8>, aad: &[u8], nonce: &[u8; N]) -> Result<(), AeadError>;

    /// Decrypt the message in-place, returning an error in the event the provided authentication
    /// tag does not match the given ciphertext. The buffer will be truncated to the length of the
    /// original plaintext message upon success.
    fn decrypt(&self, msg: &mut Vec<u8>, aad: &[u8], nonce: &[u8; N]) -> Result<(), AeadError>;
}

// Private  implementation of an AEAD which is generic over Nonce size and Tag size. This should
// only be exposed publicly by wrapper types which provide the correctly sized const generics.
struct AeadImpl<const N: usize, const T: usize>(*mut EVP_AEAD_CTX);

enum AeadType {
    Aes128GcmSiv,
    Aes256GcmSiv,
}

fn get_evp_ctx(aead_type: AeadType) -> *const EVP_AEAD {
    unsafe {
        match aead_type {
            AeadType::Aes128GcmSiv => bssl_sys::EVP_aead_aes_128_gcm_siv(),
            AeadType::Aes256GcmSiv => bssl_sys::EVP_aead_aes_256_gcm_siv(),
        }
    }
}

impl<const N: usize, const T: usize> AeadImpl<N, T> {
    // Create a new AeadImpl instance from key material and for a supported AeadType. When using
    // this helper, the caller needs to ensure the key size `K` is correct for the provided
    // AeadType.
    fn new<const K: usize>(key: &[u8; K], aead_type: AeadType) -> Self {
        // Safety:
        // - This is always safe as long as the correct key size is set by the wrapper type.
        let ctx = unsafe {
            bssl_sys::EVP_AEAD_CTX_new(
                get_evp_ctx(aead_type),
                key.as_ptr(),
                key.len(),
                bssl_sys::EVP_AEAD_DEFAULT_TAG_LENGTH as usize,
            )
        };
        assert!(!ctx.is_null());
        AeadImpl(ctx)
    }

    // Encrypts msg in-place, adding enough space to msg for the auth tag.
    fn encrypt(&self, msg: &mut Vec<u8>, aad: &[u8], nonce: &[u8; N]) -> Result<(), AeadError> {
        let msg_len = msg.len();
        // extend buffer so it has enough space to hold the auth tag
        msg.extend_from_slice(&[0u8; T]);
        let aad_cslice = CSlice::from(aad);
        let mut out_len = 0usize;

        // Safety:
        // - The output buffer is always large enough to hold the tag.
        // - The nonce is always the correct length.
        // - ctx is always already initialized.
        let result = unsafe {
            bssl_sys::EVP_AEAD_CTX_seal(
                self.0,
                msg.as_mut_ptr(),
                &mut out_len,
                msg.len(),
                nonce.as_ptr(),
                nonce.len(),
                msg.as_mut_ptr(),
                msg_len,
                aad_cslice.as_ptr(),
                aad_cslice.len(),
            )
        };

        if result == 1 {
            // Verify the correct number of bytes were written.
            assert_eq!(out_len, msg.len());
            Ok(())
        } else {
            // Restore message buffer to its original size
            msg.drain(msg_len..);
            Err(AeadError)
        }
    }

    // Decrypts msg in-place, on success msg will contain the plain text alone, without the auth
    // tag.
    fn decrypt(&self, msg: &mut Vec<u8>, aad: &[u8], nonce: &[u8; N]) -> Result<(), AeadError> {
        // Verify the message is long enough to contain an auth tag.
        if msg.len() < T {
            return Err(AeadError);
        }

        let aad_cslice = CSlice::from(aad);
        let mut out_len = 0usize;

        // Safety:
        // - The nonce is always the correct length.
        // - ctx is always already initialized.
        let result = unsafe {
            bssl_sys::EVP_AEAD_CTX_open(
                self.0,
                msg.as_mut_ptr(),
                &mut out_len,
                msg.len(),
                nonce.as_ptr(),
                nonce.len(),
                msg.as_ptr(),
                msg.len(),
                aad_cslice.as_ptr(),
                aad_cslice.len(),
            )
        };

        if result == 1 {
            // Verify the correct number of bytes were written.
            assert_eq!(out_len, msg.len() - T);
            // Chop off the tag so vec now just contains the plaintext.
            msg.drain(out_len..);
            Ok(())
        } else {
            Err(AeadError)
        }
    }
}
