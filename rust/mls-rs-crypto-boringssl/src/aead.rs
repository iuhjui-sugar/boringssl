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

use bssl_crypto::aead::{Aead, Aes128Gcm, Aes256Gcm, Chacha20Poly1305};
use mls_rs_core::{crypto::CipherSuite, error::IntoAnyError};
use mls_rs_crypto_traits::{AeadId, AeadType, AES_TAG_LEN};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AeadError {
    #[error("AEAD ciphertext was invalid")]
    InvalidCiphertext,
    #[error("AEAD ciphertext of length {0} is too short to fit the tag")]
    InvalidCipherLen(usize),
    #[error("encrypted message cannot be empty")]
    EmptyPlaintext,
    #[error("AEAD key of invalid length {0}. Expected length {1}")]
    InvalidKeyLen(usize, usize),
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

impl IntoAnyError for AeadError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

pub struct AeadWrapper(AeadId);

impl AeadWrapper {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        AeadId::new(cipher_suite).map(Self)
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl AeadType for AeadWrapper {
    type Error = AeadError;

    #[allow(clippy::needless_lifetimes)]
    async fn seal<'a>(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&'a [u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        (!data.is_empty())
            .then_some(())
            .ok_or(AeadError::EmptyPlaintext)?;

        (key.len() == self.key_size())
            .then_some(())
            .ok_or_else(|| AeadError::InvalidKeyLen(key.len(), self.key_size()))?;

        let nonce = nonce[0..self.nonce_size()].try_into().unwrap();

        match self.0 {
            AeadId::Aes128Gcm => {
                let cipher = Aes128Gcm::new(key[0..self.key_size()].try_into().unwrap());
                Ok(cipher.seal(nonce, data, aad.unwrap_or_default()))
            }
            AeadId::Aes256Gcm => {
                let cipher = Aes256Gcm::new(key[0..self.key_size()].try_into().unwrap());
                Ok(cipher.seal(nonce, data, aad.unwrap_or_default()))
            }
            AeadId::Chacha20Poly1305 => {
                let cipher = Chacha20Poly1305::new(key[0..self.key_size()].try_into().unwrap());
                Ok(cipher.seal(nonce, data, aad.unwrap_or_default()))
            }
            _ => Err(AeadError::UnsupportedCipherSuite),
        }
    }

    #[allow(clippy::needless_lifetimes)]
    async fn open<'a>(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&'a [u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        (ciphertext.len() > AES_TAG_LEN)
            .then_some(())
            .ok_or(AeadError::InvalidCipherLen(ciphertext.len()))?;

        (key.len() == self.key_size())
            .then_some(())
            .ok_or_else(|| AeadError::InvalidKeyLen(key.len(), self.key_size()))?;

        let nonce = nonce[0..self.nonce_size()].try_into().unwrap();

        match self.0 {
            AeadId::Aes128Gcm => {
                let cipher = Aes128Gcm::new(key[0..self.key_size()].try_into().unwrap());
                let res = cipher.open(nonce, ciphertext, aad.unwrap_or_default());
                match res {
                    Some(x) => Ok(x),
                    None => Err(AeadError::InvalidCiphertext),
                }
            }
            AeadId::Aes256Gcm => {
                let cipher = Aes256Gcm::new(key[0..self.key_size()].try_into().unwrap());
                let res = cipher.open(nonce, ciphertext, aad.unwrap_or_default());
                match res {
                    Some(x) => Ok(x),
                    None => Err(AeadError::InvalidCiphertext),
                }
            }
            AeadId::Chacha20Poly1305 => {
                let cipher = Chacha20Poly1305::new(key[0..self.key_size()].try_into().unwrap());
                let res = cipher.open(nonce, ciphertext, aad.unwrap_or_default());
                match res {
                    Some(x) => Ok(x),
                    None => Err(AeadError::InvalidCiphertext),
                }
            }
            _ => Err(AeadError::UnsupportedCipherSuite),
        }
    }

    #[inline(always)]
    fn key_size(&self) -> usize {
        self.0.key_size()
    }

    fn nonce_size(&self) -> usize {
        self.0.nonce_size()
    }

    fn aead_id(&self) -> u16 {
        self.0 as u16
    }
}

#[cfg(all(not(mls_build_async), test))]
mod test {
    use mls_rs_core::crypto::CipherSuite;
    use mls_rs_crypto_traits::{AeadType, AES_TAG_LEN};

    use super::{AeadWrapper, AeadError};

    use assert_matches::assert_matches;

    fn get_aeads() -> Vec<AeadWrapper> {
        [
            CipherSuite::CURVE25519_AES128,
            CipherSuite::CURVE25519_CHACHA,
            CipherSuite::CURVE448_AES256,
        ]
        .into_iter()
        .map(|v| AeadWrapper::new(v).unwrap())
        .collect()
    }

    #[test]
    fn encrypt_decrypt() {
        for aead in get_aeads() {
            let key = vec![42u8; aead.key_size()];
            let nonce = vec![42u8; aead.nonce_size()];

            let plaintext = b"message";
            let ciphertext = aead.seal(&key, plaintext, None, &nonce).unwrap();
            assert_eq!(
                plaintext,
                aead.open(&key, ciphertext.as_slice(), None, &nonce).unwrap().as_slice()
            );
        }
    }

    #[test]
    fn invalid_key() {
        for aead in get_aeads() {
            let nonce = vec![42u8; aead.nonce_size()];
            let data = b"top secret";

            let too_short = vec![42u8; aead.key_size() - 1];

            assert_matches!(
                aead.seal(&too_short, data, None, &nonce),
                Err(AeadError::InvalidKeyLen(_, _))
            );

            let too_long = vec![42u8; aead.key_size() + 1];

            assert_matches!(
                aead.seal(&too_long, data, None, &nonce),
                Err(AeadError::InvalidKeyLen(_, _))
            );
        }
    }

    #[test]
    fn invalid_ciphertext() {
        for aead in get_aeads() {
            let key = vec![42u8; aead.key_size()];
            let nonce = vec![42u8; aead.nonce_size()];

            let too_short = [0u8; AES_TAG_LEN];

            assert_matches!(
                aead.open(&key, &too_short, None, &nonce),
                Err(AeadError::InvalidCipherLen(_))
            );
        }
    }

    #[test]
    fn aad_mismatch() {
        for aead in get_aeads() {
            let key = vec![42u8; aead.key_size()];
            let nonce = vec![42u8; aead.nonce_size()];

            let ciphertext = aead.seal(&key, b"message", Some(b"foo"), &nonce).unwrap();

            assert_matches!(
                aead.open(&key, &ciphertext, Some(b"bar"), &nonce),
                Err(AeadError::InvalidCiphertext)
            );

            assert_matches!(
                aead.open(&key, &ciphertext, None, &nonce),
                Err(AeadError::InvalidCiphertext)
            );
        }
    }
}
