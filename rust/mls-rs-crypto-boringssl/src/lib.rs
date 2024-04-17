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

pub mod aead;
pub mod ec_signer;
pub mod ecdh;
pub mod hpke;
pub mod kdf;
pub mod mac;

#[cfg(test)]
mod test_helpers;

use mls_rs_core::crypto::{CipherSuite, CipherSuiteProvider, CryptoProvider,
	SignaturePublicKey, SignatureSecretKey,
};
use mls_rs_core::error::{AnyError, IntoAnyError};
use mls_rs_crypto_traits::{DhType, KdfType, AeadType};

use aead::AeadWrapper;
use ec_signer::{EcSigner, EcSignerError};
use ecdh::Ecdh;
use kdf::Kdf;
use hpke::{ContextR, ContextS};
use mac::{Hash, HashError};

use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum BoringsslCryptoError {
    #[error(transparent)]
    HashError(#[from] HashError),
    #[error(transparent)]
    KdfError(AnyError),
    #[error(transparent)]
    AeadError(AnyError),
    #[error(transparent)]
    EcSignerError(#[from] EcSignerError),
}

impl IntoAnyError for BoringsslCryptoError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}


#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BoringsslCryptoProvider {
    pub enabled_cipher_suites: Vec<CipherSuite>,
}

impl BoringsslCryptoProvider {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_enabled_cipher_suites(enabled_cipher_suites: Vec<CipherSuite>) -> Self {
        Self { enabled_cipher_suites }
    }

    pub fn all_supported_cipher_suites() -> Vec<CipherSuite> {
        CipherSuite::all().collect()
    }
}

impl Default for BoringsslCryptoProvider {
    fn default() -> Self {
        Self { enabled_cipher_suites: Self::all_supported_cipher_suites() }
    }
}

impl CryptoProvider for BoringsslCryptoProvider {
    type CipherSuiteProvider = BoringsslCipherSuite</*Ecdh, */Kdf, AeadWrapper>;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        self.enabled_cipher_suites.clone()
    }

    fn cipher_suite_provider(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        if !self.enabled_cipher_suites.contains(&cipher_suite) {
            return None;
        }

        // let ecdh = Ecdh::new(cipher_suite)?;
        let kdf = Kdf::new(cipher_suite)?;
        // let kem_id = KemId::new(cipher_suite)?;
        // let kem = DhKem::new(ecdh, kdf.clone(), kem_id as u16, kem_id.n_secret());
        let aead = AeadWrapper::new(cipher_suite)?;

        BoringsslCipherSuite::new(cipher_suite, /*ecdh, */kdf, aead)
    }
}

#[derive(Clone)]
pub struct BoringsslCipherSuite</*DH, */KDF, AEAD>
where
    // DH: DhType + Clone,
    KDF: KdfType + Clone,
    AEAD: AeadType + Clone,
{
    cipher_suite: CipherSuite,
    hash: Hash,
    kdf: KDF,
    aead: AEAD,
    // hpke: Hpke<KEM, KDF, AEAD>,
    ec_signer: EcSigner,
}

impl</*DH, */KDF, AEAD> BoringsslCipherSuite</*DH, */KDF, AEAD>
where
    // DH: DhType + Clone,
    KDF: KdfType + Clone,
    AEAD: AeadType + Clone,
{
    pub fn new(cipher_suite: CipherSuite, /*dh: DH, */kdf: KDF, aead: AEAD) -> Option<Self> {
        // let hpke = Hpke::new(kem, kdf.clone(), Some(aead.clone()));

        Some(Self {
            cipher_suite,
            kdf,
            aead,
            hash: Hash::new(cipher_suite).ok()?,
            // hpke,
            ec_signer: EcSigner::new(cipher_suite)?,
        })
    }

    pub fn random_bytes(&self, out: &mut [u8]) -> Result<(), BoringsslCryptoError> {
        unimplemented!();
    }

    pub fn import_der_public_signing_key(
        &self,
        der_data: &[u8],
    ) -> Result<SignaturePublicKey, BoringsslCryptoError> {
        unimplemented!();
    }

    pub fn import_der_private_signing_key(
        &self,
        der_data: &[u8],
    ) -> Result<SignatureSecretKey, BoringsslCryptoError> {
        unimplemented!();
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl</*DH, */KDF, AEAD> CipherSuiteProvider for BoringsslCipherSuite</*DH, */KDF, AEAD>
where
    // DH: DhType + Clone + Send + Sync,
    KDF: KdfType + Clone + Send + Sync,
    AEAD: AeadType + Clone + Send + Sync,
{
    type Error = BoringsslCryptoError;
    type HpkeContextS = ContextS;
    type HpkeContextR = ContextR;

    fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    async fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.hash.hash(data))
    }

    async fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.hash.mac(key, data)?)
    }

    async fn kdf_extract(
        &self,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf
            .extract(salt, ikm)
            .await
            .map_err(|e| BoringsslCryptoError::KdfError(e.into_any_error()))
            .map(Zeroizing::new)
    }

    async fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf
            .expand(prk, info, len)
            .await
            .map_err(|e| BoringsslCryptoError::KdfError(e.into_any_error()))
            .map(Zeroizing::new)
    }

    fn kdf_extract_size(&self) -> usize {
        self.kdf.extract_size()
    }

    async fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.aead
            .seal(key, data, aad, nonce)
            .await
            .map_err(|e| BoringsslCryptoError::AeadError(e.into_any_error()))
    }

    async fn aead_open(
        &self,
        key: &[u8],
        cipher_text: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.aead
            .open(key, cipher_text, aad, nonce)
            .await
            .map_err(|e| BoringsslCryptoError::AeadError(e.into_any_error()))
            .map(Zeroizing::new)
    }

    fn aead_key_size(&self) -> usize {
        self.aead.key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.aead.nonce_size()
    }

    async fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        Ok(self.ec_signer.signature_key_generate()?)
    }

    async fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        Ok(self.ec_signer.signature_key_derive_public(secret_key)?)
    }

    async fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(self.ec_signer.sign(secret_key, data)?)
    }

    async fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        Ok(self.ec_signer.verify(public_key, signature, data)?)
    }
}
