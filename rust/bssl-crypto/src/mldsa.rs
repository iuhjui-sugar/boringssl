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
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

//! ML-DSA
//!
//! ML-DSA is a post-quantum key signature scheme, specified in
//! [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).
//!
//! ```
//! use bssl_crypto::mldsa;
//!
//! // Generate a key pair.
//! let (serialized_public_key, private_key, _private_seed) = mldsa::PrivateKey65::generate();
//!
//! // Send `serialized_public_key` to the verifier. The verifier parses it:
//! let public_key = mldsa::PublicKey65::parse(&serialized_public_key).unwrap();
//!
//! // The signer signs a message.
//! let message = &[0u8, 1, 2, 3];
//! let signature = private_key.sign(message);
//!
//! // Send `message` and `signature` to the verifier. The verifier checks the signature.
//! assert!(public_key.verify(message, &signature).is_ok());
//! ```

use crate::{
    cbb_to_array, initialized_struct, with_output_array, with_output_array_fallible, FfiSlice,
    InvalidSignatureError,
};
use core::mem::MaybeUninit;

/// An ML-DSA-65 private key.
pub struct PrivateKey65(bssl_sys::MLDSA65_private_key);

/// An ML-DSA-65 public key.
pub struct PublicKey65(bssl_sys::MLDSA65_public_key);

/// The number of bytes in an encoded ML-DSA-65 public key.
pub const PUBLIC_KEY_BYTES_65: usize = bssl_sys::MLDSA65_PUBLIC_KEY_BYTES as usize;

/// The number of bytes in an encoded ML-DSA-65 signature.
pub const SIGNATURE_BYTES_65: usize = bssl_sys::MLDSA65_SIGNATURE_BYTES as usize;

/// The number of bytes in an ML-DSA seed value.
pub const SEED_BYTES: usize = bssl_sys::MLDSA_SEED_BYTES as usize;

impl PrivateKey65 {
    /// Generates a random public/private key pair returning a serialized public
    /// key, a private key, and a private seed value that can be used to
    /// regenerate the same private key in the future.
    pub fn generate() -> ([u8; PUBLIC_KEY_BYTES_65], Self, [u8; SEED_BYTES]) {
        let mut public_key_bytes = MaybeUninit::<[u8; PUBLIC_KEY_BYTES_65]>::uninit();
        let mut private_key = MaybeUninit::<PrivateKey65>::uninit();
        let mut seed = MaybeUninit::<[u8; SEED_BYTES]>::uninit();

        unsafe {
            // Safety: the buffers are the sizes that the FFI code requires.
            let ok = bssl_sys::MLDSA65_generate_key(
                public_key_bytes.as_mut_ptr() as *mut u8,
                seed.as_mut_ptr() as *mut u8,
                &mut (*private_key.as_mut_ptr()).0,
            );
            // This function can only fail if out of memory, which is not a
            // case that this crate handles.
            assert_eq!(ok, 1);
            (
                // Safety: the buffers are always fully initialized by
                // `MLDSA65_generate_key`.
                public_key_bytes.assume_init(),
                private_key.assume_init(),
                seed.assume_init(),
            )
        }
    }

    /// Regenerates a private key from a seed value.
    pub fn from_seed(seed: &[u8; SEED_BYTES]) -> Self {
        Self(unsafe {
            // Safety: `priv_key` is the correct size via the type system and
            // is always fully written.
            initialized_struct(|priv_key| {
                let ok = bssl_sys::MLDSA65_private_key_from_seed(
                    priv_key,
                    seed.as_ffi_ptr(),
                    seed.len(),
                );
                // Since the seed value has the correct length, this function can
                // never fail.
                assert_eq!(ok, 1);
            })
        })
    }

    /// Derives the public key corresponding to this private key.
    pub fn to_public_key(&self) -> PublicKey65 {
        PublicKey65(unsafe {
            // Safety: `pub_key` is the correct size via the type system and
            // is always fully written.
            initialized_struct(|pub_key| {
                bssl_sys::MLDSA65_public_from_private(pub_key, &self.0);
            })
        })
    }

    /// Signs a message using this private key.
    pub fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_BYTES_65] {
        unsafe {
            // Safety: `signature` is the correct size via the type system and
            // is always fully written.
            with_output_array(|signature, _| {
                let ok = bssl_sys::MLDSA65_sign(
                    signature,
                    &self.0,
                    msg.as_ffi_ptr(),
                    msg.len(),
                    core::ptr::null(),
                    0,
                );
                // This function can only fail if out of memory, which is not a
                // case that this crate handles.
                assert_eq!(ok, 1);
            })
        }
    }

    /// Signs a message using this private key and the given context.
    ///
    /// This function returns None if `context` is longer than 255 bytes.
    pub fn sign_with_context(
        &self,
        msg: &[u8],
        context: &[u8],
    ) -> Option<[u8; SIGNATURE_BYTES_65]> {
        unsafe {
            // Safety: `signature` is the correct size via the type system and
            // is always fully written.
            with_output_array_fallible(|signature, _| {
                bssl_sys::MLDSA65_sign(
                    signature,
                    &self.0,
                    msg.as_ffi_ptr(),
                    msg.len(),
                    context.as_ffi_ptr(),
                    context.len(),
                ) == 1
            })
        }
    }
}

impl PublicKey65 {
    /// Parses a public key from a byte slice.
    pub fn parse(encoded: &[u8]) -> Option<Self> {
        let mut public_key = MaybeUninit::<PublicKey65>::uninit();
        let mut cbs = bssl_sys::CBS {
            data: encoded.as_ptr(),
            len: encoded.len(),
        };

        unsafe {
            // Safety: `public_key` is the correct size via the type system and
            // is fully written if this function returns 1.
            let result =
                bssl_sys::MLDSA65_parse_public_key(&mut (*public_key.as_mut_ptr()).0, &mut cbs);

            if result == 1 && cbs.len == 0 {
                Some(public_key.assume_init())
            } else {
                None
            }
        }
    }

    /// Return the serialization of this public key.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_BYTES_65] {
        unsafe {
            cbb_to_array(|cbb| {
                let ok = bssl_sys::MLDSA65_marshal_public_key(cbb, &self.0);
                // `MLKEM768_marshal_public_key` only fails if it cannot
                // allocate memory, but `cbb_to_array` writes into a fixed
                // buffer.
                assert_eq!(ok, 1);
            })
        }
    }

    /// Verifies a signature for a given message using this public key.
    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), InvalidSignatureError> {
        unsafe {
            let ok = bssl_sys::MLDSA65_verify(
                &self.0,
                signature.as_ffi_ptr(),
                signature.len(),
                msg.as_ffi_ptr(),
                msg.len(),
                core::ptr::null(),
                0,
            );
            if ok == 1 {
                Ok(())
            } else {
                Err(InvalidSignatureError)
            }
        }
    }

    /// Verifies a signature for a given message using this public key and the given context.
    pub fn verify_with_context(
        &self,
        msg: &[u8],
        signature: &[u8],
        context: &[u8],
    ) -> Result<(), InvalidSignatureError> {
        unsafe {
            let ok = bssl_sys::MLDSA65_verify(
                &self.0,
                signature.as_ffi_ptr(),
                signature.len(),
                msg.as_ffi_ptr(),
                msg.len(),
                context.as_ffi_ptr(),
                context.len(),
            );
            if ok == 1 {
                Ok(())
            } else {
                Err(InvalidSignatureError)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic() {
        let (serialized_public_key, private_key, private_seed) = PrivateKey65::generate();
        let public_key = PublicKey65::parse(&serialized_public_key).unwrap();
        let message = &[0u8, 1, 2, 3];
        let signature = private_key.sign(message);
        let private_key2 = PrivateKey65::from_seed(&private_seed);
        let mut signature2 = private_key2.sign(message);
        assert!(public_key.verify(message, &signature).is_ok());
        assert!(public_key.verify(message, &signature2).is_ok());

        signature2[5] ^= 1;
        assert!(public_key.verify(message, &signature2).is_err());

        let context = b"context";
        let signature3 = private_key.sign_with_context(message, context).unwrap();
        assert!(public_key.verify(message, &signature3).is_err());
        assert!(public_key
            .verify_with_context(message, &signature3, context)
            .is_ok());
    }

    #[test]
    fn marshal_public_key() {
        let (serialized_public_key, private_key, _) = PrivateKey65::generate();
        let public_key = PublicKey65::parse(&serialized_public_key).unwrap();
        assert_eq!(serialized_public_key, public_key.to_bytes());
        assert_eq!(
            serialized_public_key,
            private_key.to_public_key().to_bytes()
        );
    }
}
