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

use bssl_crypto::x25519;
use mls_rs_core::crypto::{CipherSuite, HpkePublicKey, HpkeSecretKey};
use mls_rs_core::error::IntoAnyError;
use mls_rs_crypto_traits::{Curve, DhType};

#[cfg(not(feature = "std"))]
use core::array::TryFromSliceError;
#[cfg(feature = "std")]
use std::array::TryFromSliceError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EcdhKemError {
    #[error(transparent)]
    TryFromSliceError(TryFromSliceError),
    #[error("ECDH public key was invalid")]
    InvalidPublicKey,
    #[error("ECDH key of invalid length {0}. Expected length {1}")]
    InvalidKeyLen(usize, usize),
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

impl IntoAnyError for EcdhKemError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

impl From<TryFromSliceError> for EcdhKemError {
    fn from(e: TryFromSliceError) -> Self {
        EcdhKemError::TryFromSliceError(e)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ecdh(Curve);

impl Ecdh {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        Curve::from_ciphersuite(cipher_suite, /*for_sig=*/ false).map(Self)
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl DhType for Ecdh {
    type Error = EcdhKemError;

    async fn dh(
        &self,
        secret_key: &HpkeSecretKey,
        public_key: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        (self.0 == Curve::X25519)
            .then_some(())
            .ok_or(EcdhKemError::UnsupportedCipherSuite)?;

        (secret_key.len() == x25519::PRIVATE_KEY_LEN)
            .then_some(())
            .ok_or_else(|| {
                EcdhKemError::InvalidKeyLen(secret_key.len(), x25519::PRIVATE_KEY_LEN)
            })?;

        (public_key.len() == x25519::PUBLIC_KEY_LEN)
            .then_some(())
            .ok_or_else(|| EcdhKemError::InvalidKeyLen(public_key.len(), x25519::PUBLIC_KEY_LEN))?;

        let private_key = x25519::PrivateKey(secret_key[0..x25519::PRIVATE_KEY_LEN].try_into()?);
        let shared_key =
            private_key.compute_shared_key(public_key[0..x25519::PUBLIC_KEY_LEN].try_into()?);
        match shared_key {
            Some(x) => Ok(x.to_vec()),
            None => Err(EcdhKemError::InvalidPublicKey),
        }
    }

    async fn to_public(&self, secret_key: &HpkeSecretKey) -> Result<HpkePublicKey, Self::Error> {
        (self.0 == Curve::X25519)
            .then_some(())
            .ok_or(EcdhKemError::UnsupportedCipherSuite)?;

        (secret_key.len() == x25519::PRIVATE_KEY_LEN)
            .then_some(())
            .ok_or_else(|| {
                EcdhKemError::InvalidKeyLen(secret_key.len(), x25519::PRIVATE_KEY_LEN)
            })?;

        let private_key = x25519::PrivateKey(secret_key[0..x25519::PRIVATE_KEY_LEN].try_into()?);
        Ok(private_key.to_public().to_vec().into())
    }

    async fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        (self.0 == Curve::X25519)
            .then_some(())
            .ok_or(EcdhKemError::UnsupportedCipherSuite)?;

        let (public_key, private_key) = x25519::PrivateKey::generate();
        Ok((private_key.0.to_vec().into(), public_key.to_vec().into()))
    }

    fn bitmask_for_rejection_sampling(&self) -> Option<u8> {
        self.0.curve_bitmask()
    }

    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        (self.0 == Curve::X25519)
            .then_some(())
            .ok_or(EcdhKemError::UnsupportedCipherSuite)?;

        // bssl_crypto does not implement validation of curve25519 public keys.
        // Note: neither does x25519_dalek used by RustCrypto's implementation of this function.
        (key.len() == x25519::PUBLIC_KEY_LEN)
            .then_some(())
            .ok_or_else(|| EcdhKemError::InvalidKeyLen(key.len(), x25519::PUBLIC_KEY_LEN))
    }

    fn secret_key_size(&self) -> usize {
        self.0.secret_key_size()
    }
}

#[cfg(all(not(mls_build_async), test))]
mod test {
    use mls_rs_core::crypto::{CipherSuite, HpkePublicKey, HpkeSecretKey};

    use super::{DhType, Ecdh, EcdhKemError};

    use crate::test_helpers::decode_hex;
    use assert_matches::assert_matches;

    #[test]
    fn dh() {
        // https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/x25519_test.json#L23
        let public_key = HpkePublicKey::from(
            decode_hex::<32>("504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829")
                .to_vec(),
        );
        let private_key = HpkeSecretKey::from(
            decode_hex::<32>("c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475")
                .to_vec(),
        );
        let expected_shared_secret: [u8; 32] =
            decode_hex("436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320");

        let x25519 = Ecdh::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert_eq!(
            x25519.dh(&private_key, &public_key).unwrap(),
            expected_shared_secret
        );
    }

    #[test]
    fn to_public() {
        // https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1
        let private_key = HpkeSecretKey::from(
            decode_hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .to_vec(),
        );
        let expected_public_key = HpkePublicKey::from(
            decode_hex::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .to_vec(),
        );

        let x25519 = Ecdh::new(CipherSuite::CURVE25519_CHACHA).unwrap();
        assert_eq!(x25519.to_public(&private_key).unwrap(), expected_public_key);
    }

    #[test]
    fn generate() {
        let x25519 = Ecdh::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert!(x25519.generate().is_ok());
    }

    #[test]
    fn public_key_validate() {
        let public_key = HpkePublicKey::from(
            decode_hex::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .to_vec(),
        );

        let x25519 = Ecdh::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert!(x25519.public_key_validate(&public_key).is_ok());
    }

    #[test]
    fn unsupported_cipher_suites() {
        assert_matches!(
            Ecdh::new(CipherSuite::P256_AES128).unwrap().generate(),
            Err(EcdhKemError::UnsupportedCipherSuite)
        );
        assert_matches!(
            Ecdh::new(CipherSuite::P384_AES256).unwrap().generate(),
            Err(EcdhKemError::UnsupportedCipherSuite)
        );
        assert_matches!(
            Ecdh::new(CipherSuite::P521_AES256).unwrap().generate(),
            Err(EcdhKemError::UnsupportedCipherSuite)
        );
        assert_matches!(
            Ecdh::new(CipherSuite::CURVE448_AES256).unwrap().generate(),
            Err(EcdhKemError::UnsupportedCipherSuite)
        );
    }
}
