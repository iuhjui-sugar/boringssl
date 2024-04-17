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

use bssl_crypto::ed25519;
use mls_rs_core::crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey};
use mls_rs_crypto_traits::Curve;

#[cfg(not(feature = "std"))]
use core::array::TryFromSliceError;
#[cfg(feature = "std")]
use std::array::TryFromSliceError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EcSignerError {
    #[error(transparent)]
    TryFromSliceError(TryFromSliceError),
    #[error("invalid signature")]
    InvalidSignature(bssl_crypto::InvalidSignatureError),
    #[error("EC Signer key of invalid length {0}. Expected length >= {1}")]
    InvalidKeyLen(usize, usize),
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

impl From<TryFromSliceError> for EcSignerError {
    fn from(e: TryFromSliceError) -> Self {
        EcSignerError::TryFromSliceError(e)
    }
}

impl From<bssl_crypto::InvalidSignatureError> for EcSignerError {
    fn from(e: bssl_crypto::InvalidSignatureError) -> Self {
        EcSignerError::InvalidSignature(e)
    }
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct EcSigner(Curve);

impl EcSigner {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        Curve::from_ciphersuite(
            cipher_suite,
            /*for_sig=*/
            true,
        ).map(Self)
    }

    pub fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), EcSignerError> {
        (self.0 == Curve::Ed25519).then_some(()).ok_or(
            EcSignerError::UnsupportedCipherSuite,
        )?;

        let private_key = ed25519::PrivateKey::generate();
        let public_key = private_key.to_public();
        Ok((
            private_key.as_bytes().to_vec().into(),
            public_key.as_bytes().to_vec().into(),
        ))
    }

    pub fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, EcSignerError> {
        (self.0 == Curve::Ed25519).then_some(()).ok_or(
            EcSignerError::UnsupportedCipherSuite,
        )?;

        (secret_key.len() >= ed25519::SEED_LEN)
            .then_some(())
            .ok_or_else(|| {
                EcSignerError::InvalidKeyLen(secret_key.len(), ed25519::SEED_LEN)
            })?;

        let private_key = ed25519::PrivateKey::from_seed(secret_key[0..ed25519::SEED_LEN].try_into()?);
        Ok(private_key.to_public().as_bytes().to_vec().into())
    }

    pub fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, EcSignerError> {
        (self.0 == Curve::Ed25519).then_some(()).ok_or(
            EcSignerError::UnsupportedCipherSuite,
        )?;

        (secret_key.len() >= ed25519::SEED_LEN)
            .then_some(())
            .ok_or_else(|| {
                EcSignerError::InvalidKeyLen(secret_key.len(), ed25519::SEED_LEN)
            })?;

        let private_key = ed25519::PrivateKey::from_seed(secret_key[0..ed25519::SEED_LEN].try_into()?);
        Ok(private_key.sign(data).to_vec())
    }

    pub fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), EcSignerError> {
        (self.0 == Curve::Ed25519).then_some(()).ok_or(
            EcSignerError::UnsupportedCipherSuite,
        )?;

        (public_key.len() == ed25519::PUBLIC_KEY_LEN)
            .then_some(())
            .ok_or_else(|| {
                EcSignerError::InvalidKeyLen(public_key.len(), ed25519::PUBLIC_KEY_LEN)
            })?;

        (signature.len() == ed25519::SIGNATURE_LEN)
            .then_some(())
            .ok_or(EcSignerError::InvalidKeyLen(
                signature.len(),
                ed25519::SIGNATURE_LEN,
            ))?;

        let public_key = ed25519::PublicKey::from_bytes(
            public_key.as_bytes()[0..ed25519::PUBLIC_KEY_LEN].try_into()?,
        );
        public_key.verify(
            data,
            signature[0..ed25519::SIGNATURE_LEN].try_into()?,
        )?;
        Ok(())
    }
}

#[cfg(all(not(mls_build_async), test))]
mod test {
    use mls_rs_core::crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey};

    use super::{EcSigner, EcSignerError};

    use assert_matches::assert_matches;
    use crate::test_helpers::decode_hex;

    #[test]
    fn signature_key_generate() {
        let ed25519 = EcSigner::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert!(ed25519.signature_key_generate().is_ok());
    }

    #[test]
    fn signature_key_derive_public() {
        // Test 1 from https://www.rfc-editor.org/rfc/rfc8032#section-7.1
        let private_key = SignatureSecretKey::from(
                decode_hex::<64>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").to_vec());
        let expected_public_key = SignaturePublicKey::from(
                decode_hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").to_vec(),
        );

        let ed25519 = EcSigner::new(CipherSuite::CURVE25519_CHACHA).unwrap();
        assert_eq!(
            ed25519.signature_key_derive_public(&private_key).unwrap(),
            expected_public_key
        );
    }

    #[test]
    fn sign_verify() {
        // Test 3 from https://www.rfc-editor.org/rfc/rfc8032#section-7.1
        let private_key = SignatureSecretKey::from(
                decode_hex::<64>("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025").to_vec());
        let data : [u8; 2] = decode_hex("af82");
        let expected_sig = decode_hex::<64>("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a").to_vec();

        let ed25519 = EcSigner::new(CipherSuite::CURVE25519_AES128).unwrap();
        let sig = ed25519.sign(&private_key, &data).unwrap();
        assert_eq!(sig, expected_sig);

        let public_key = ed25519.signature_key_derive_public(&private_key).unwrap();
        assert!(ed25519.verify(&public_key, &sig, &data).is_ok());
    }

    #[test]
    fn unsupported_cipher_suites() {
        assert_matches!(
            EcSigner::new(CipherSuite::P256_AES128).unwrap().signature_key_generate(),
            Err(EcSignerError::UnsupportedCipherSuite)
        );
        assert_matches!(
            EcSigner::new(CipherSuite::P384_AES256).unwrap().signature_key_generate(),
            Err(EcSignerError::UnsupportedCipherSuite)
        );
        assert_matches!(
            EcSigner::new(CipherSuite::P521_AES256).unwrap().signature_key_generate(),
            Err(EcSignerError::UnsupportedCipherSuite)
        );
        assert_matches!(
            EcSigner::new(CipherSuite::CURVE448_AES256).unwrap().signature_key_generate(),
            Err(EcSignerError::UnsupportedCipherSuite)
        );
    }
}
