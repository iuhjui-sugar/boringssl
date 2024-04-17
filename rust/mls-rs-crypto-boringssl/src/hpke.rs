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

use bssl_crypto::hpke;
use mls_rs_core::crypto::{CipherSuite, HpkeCiphertext, HpkeContextR, HpkeContextS, HpkePublicKey, HpkeSecretKey};
use mls_rs_core::error::{AnyError, IntoAnyError};
use mls_rs_crypto_traits::{DhType, KemId, KemType, KemResult, KdfType};
use std::sync::Mutex;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HpkeError {
	#[error("BoringSSL error")]
	BoringsslError,
    #[error(transparent)]
    DhError(AnyError),
    #[error(transparent)]
    KdfError(AnyError),
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

impl IntoAnyError for HpkeError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HpkeKdf<K: KdfType> {
    suite_id: Vec<u8>,
    kdf: K,
}

impl<K: KdfType> HpkeKdf<K> {
    pub fn new(suite_id: Vec<u8>, kdf: K) -> Self {
        Self { suite_id, kdf }
    }

    // https://www.rfc-editor.org/rfc/rfc9180.html#section-4-9
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn labeled_extract(
        &self,
        salt: &[u8],
        label: &[u8],
        ikm: &[u8],
    ) -> Result<Vec<u8>, <K as KdfType>::Error> {
        self.kdf
            .extract(
                salt,
                &[b"HPKE-v1" as &[u8], &self.suite_id, label, ikm].concat(),
            )
            .await
    }

    // https://www.rfc-editor.org/rfc/rfc9180.html#section-4-9
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn labeled_expand(
        &self,
        key: &[u8],
        label: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, <K as KdfType>::Error> {
        let labeled_info = [
            &(len as u16).to_be_bytes() as &[u8],
            b"HPKE-v1",
            &self.suite_id,
            label,
            info,
        ]
        .concat();
        self.kdf.expand(key, &labeled_info, len).await
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhKem<DH: DhType, KDF: KdfType> {
    dh: DH,
    kdf: HpkeKdf<KDF>,
    kem_id: KemId,
    n_secret: usize,
}

impl<DH: DhType, KDF: KdfType> DhKem<DH, KDF> {
    pub fn new(cipher_suite: CipherSuite, dh: DH, kdf: KDF) -> Option<Self> {
        let kem_id = KemId::new(cipher_suite)?;
        let suite_id = [b"KEM", &(kem_id as u16).to_be_bytes() as &[u8]].concat();
        let kdf = HpkeKdf::new(suite_id, kdf);

        Some(Self {
            dh,
            kdf,
            kem_id,
            n_secret: kem_id.n_secret(),
        })
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl<DH: DhType, KDF: KdfType> KemType for DhKem<DH, KDF> {
    type Error = HpkeError;

    fn kem_id(&self) -> u16 {
        self.kem_id as u16
    }

    async fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        (self.kem_id == KemId::DhKemX25519Sha256)
            .then_some(())
            .ok_or(HpkeError::UnsupportedCipherSuite)?;

        let kem = hpke::Kem::X25519HkdfSha256;
        let (public_key, private_key) = kem.generate_keypair();
        Ok((private_key.to_vec().into(), public_key.to_vec().into()))
    }

    // https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.3-8
    async fn derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let dkp_prk = self.kdf
            .labeled_extract(&[], b"dkp_prk", ikm)
            .await
            .map_err(|e| HpkeError::KdfError(e.into_any_error()))?;
        let sk = self.kdf
            .labeled_expand(&dkp_prk, b"sk", &[], self.dh.secret_key_size())
            .await
            .map_err(|e| HpkeError::KdfError(e.into_any_error()))?
            .into();
        let pk = self.dh
            .to_public(&sk)
            .await
            .map_err(|e| HpkeError::DhError(e.into_any_error()))?;
        Ok((sk, pk))
    }

    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        self.dh.public_key_validate(key)
            .map_err(|e| HpkeError::DhError(e.into_any_error()))
    }

    // Using BoringSSL's HPKE implementation so this is not needed.
    async fn encap(&self, _remote_pk: &HpkePublicKey) -> Result<KemResult, Self::Error> {
        unimplemented!();
    }

    // Using BoringSSL's HPKE implementation so this is not needed.
    async fn decap(
        &self,
        _enc: &[u8],
        _secret_key: &HpkeSecretKey,
        _public_key: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        unimplemented!();
    }
}

pub struct ContextS(pub Mutex<hpke::SenderContext>);

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl HpkeContextS for ContextS {
    type Error = HpkeError;

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn seal(
    	&mut self,
        aad: Option<&[u8]>,
        data: &[u8]
    ) -> Result<Vec<u8>, Self::Error> {
        Ok((*self.0.lock().unwrap())
            .seal(data, aad.unwrap_or_default())
            .await
        )
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, Self::Error> {
        match (*self.0.lock().unwrap()).export(exporter_context, len) {
            Some(x) => Ok(x),
            None => Err(HpkeError::BoringsslError),
        }
    }
}

pub struct ContextR(pub Mutex<hpke::RecipientContext>);

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl HpkeContextR for ContextR {
    type Error = HpkeError;

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn open(
        &mut self,
        aad: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        match (*self.0.lock().unwrap()).open(ciphertext, aad.unwrap_or_default()) {
            Some(x) => Ok(x),
            None => Err(HpkeError::BoringsslError),
        }
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, Self::Error> {
        match (*self.0.lock().unwrap()).export(exporter_context, len) {
            Some(x) => Ok(x),
            None => Err(HpkeError::BoringsslError),
        }
    }
}

#[derive(Clone)]
pub struct Hpke(pub CipherSuite);

impl Hpke {
    pub fn new(cipher_suite: CipherSuite) -> Self {
        Self(cipher_suite)
    }

	#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn setup_sender(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, ContextS), HpkeError> {
    	let params = Self::cipher_suite_to_params(self.0)?;
    	match hpke::SenderContext::new(&params, &remote_key, info) {
    		Some((ctx, encapsulated_key)) => Ok((encapsulated_key, ContextS(ctx.into()))),
    		None => Err(HpkeError::BoringsslError)
    	}
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, HpkeError> {
    	let (kem_output, mut ctx) = self.setup_sender(remote_key, info).await?;
    	Ok(HpkeCiphertext {
    		kem_output,
    		ciphertext: ctx.seal(aad, pt).await?,
    	})
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn setup_receiver(
        &self,
        enc: &[u8],
        local_secret: &HpkeSecretKey,
        info: &[u8],
    ) -> Result<ContextR, HpkeError> {
		let params = Self::cipher_suite_to_params(self.0)?;
		match hpke::RecipientContext::new(&params, &local_secret, &enc, info) {
    		Some(ctx) => Ok(ContextR(ctx.into())),
    		None => Err(HpkeError::BoringsslError)
    	}
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, HpkeError> {
    	let mut ctx = self.setup_receiver(
    		&ciphertext.kem_output, local_secret, info).await?;
    	ctx.open(aad, &ciphertext.ciphertext).await
    }

    fn cipher_suite_to_params(cipher_suite: CipherSuite) -> Result<hpke::Params, HpkeError> {
    	match cipher_suite {
    		CipherSuite::CURVE25519_AES128 =>
    			Ok(hpke::Params::new(
    				hpke::Kem::X25519HkdfSha256,
    				hpke::Kdf::HkdfSha256,
    				hpke::Aead::Aes128Gcm,
    			)),
            CipherSuite::CURVE25519_CHACHA =>
            	Ok(hpke::Params::new(
    				hpke::Kem::X25519HkdfSha256,
    				hpke::Kdf::HkdfSha256,
    				hpke::Aead::Chacha20Poly1305,
    			)),
            _ => Err(HpkeError::UnsupportedCipherSuite),
    	}
    }
}

#[cfg(all(not(mls_build_async), test))]
mod test {
    use mls_rs_core::crypto::{CipherSuite, HpkeContextR, HpkeContextS, HpkePublicKey, HpkeSecretKey};
    use mls_rs_crypto_traits::{AeadId, KemId, KemType, KdfId};

    use super::{DhKem, Hpke, HpkeKdf};
    use crate::ecdh::Ecdh;
    use crate::kdf::Kdf;

    use crate::test_helpers::decode_hex;

    use std::thread;

    fn hpke_suite_id(cipher_suite: CipherSuite) -> Vec<u8> {
        [
            b"HPKE",
            &(KemId::new(cipher_suite).unwrap() as u16).to_be_bytes() as &[u8],
            &(KdfId::new(cipher_suite).unwrap() as u16).to_be_bytes() as &[u8],
            &(AeadId::new(cipher_suite).unwrap() as u16).to_be_bytes() as &[u8],
        ].concat()
    }

    #[test]
    fn hpke_kdf_labeled_extract() {
        let cipher_suite = CipherSuite::CURVE25519_AES128;
        let suite_id = hpke_suite_id(cipher_suite);
        let kdf = HpkeKdf::new(suite_id, Kdf::new(cipher_suite).unwrap());

        // https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.1
        let shared_secret : [u8; 32] = decode_hex("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
        let expected_secret : [u8; 32] = decode_hex("12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397");
        let label = b"secret";

        let secret = kdf.labeled_extract(&shared_secret, label, &[]).unwrap();
        assert_eq!(secret, expected_secret);
    }

    #[test]
    fn hpke_kdf_labeled_expand() {
        let cipher_suite = CipherSuite::CURVE25519_AES128;
        let suite_id = hpke_suite_id(cipher_suite);
        let kdf = HpkeKdf::new(suite_id, Kdf::new(cipher_suite).unwrap());

        // https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.1
        let secret : [u8; 32] = decode_hex("12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397");
        let key_schedule_ctx : [u8; 65] = decode_hex("00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449");
        let expected_key : [u8; 16] = decode_hex("4531685d41d65f03dc48f6b8302c05b0");
        let label = b"key";

        let key = kdf.labeled_expand(&secret, label, &key_schedule_ctx, 16).unwrap();
        assert_eq!(key, expected_key);
    }

    #[test]
    fn dh_kem_kem_id() {
        let cipher_suite = CipherSuite::CURVE25519_CHACHA;
        let dh = Ecdh::new(cipher_suite).unwrap();
        let kdf = Kdf::new(cipher_suite).unwrap();
        let kem = DhKem::new(cipher_suite, dh, kdf).unwrap();

        assert_eq!(kem.kem_id(), 32);
    }

    #[test]
    fn dh_kem_generate() {
        let cipher_suite = CipherSuite::CURVE25519_AES128;
        let dh = Ecdh::new(cipher_suite).unwrap();
        let kdf = Kdf::new(cipher_suite).unwrap();
        let kem = DhKem::new(cipher_suite, dh, kdf).unwrap();

        assert!(kem.generate().is_ok());
    }

    #[test]
    fn dh_kem_derive() {
        let cipher_suite = CipherSuite::CURVE25519_CHACHA;
        let dh = Ecdh::new(cipher_suite).unwrap();
        let kdf = Kdf::new(cipher_suite).unwrap();
        let kem = DhKem::new(cipher_suite, dh, kdf).unwrap();

        // https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.1
        let ikm : [u8; 32] = decode_hex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"); 
        let expected_sk = HpkeSecretKey::from(
            decode_hex::<32>("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
                .to_vec()
        );
        let expected_pk = HpkePublicKey::from(
            decode_hex::<32>("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
                .to_vec()
        );
    
        let (sk, pk) = kem.derive(&ikm).unwrap();
        assert_eq!(sk, expected_sk);
        assert_eq!(pk, expected_pk);
    }

    #[test]
    fn dh_kem_public_key_validate() {
        let cipher_suite = CipherSuite::CURVE25519_AES128;
        let dh = Ecdh::new(cipher_suite).unwrap();
        let kdf = Kdf::new(cipher_suite).unwrap();
        let kem = DhKem::new(cipher_suite, dh, kdf).unwrap();

        let public_key = HpkePublicKey::from(
            decode_hex::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .to_vec(),
        );
        assert!(kem.public_key_validate(&public_key).is_ok());
    }

    #[test]
    fn hpke_seal_open() {
        let hpke = Hpke::new(CipherSuite::CURVE25519_AES128);

        // https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.1
        let receiver_pub_key = HpkePublicKey::from(
            decode_hex::<32>("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
                .to_vec(),
        );
        let receiver_priv_key = HpkeSecretKey::from(
            decode_hex::<32>("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
                .to_vec()
        );

        let info = b"some_info";
        let plaintext = b"plaintext";
        let associated_data = b"some_ad";

        let ct = hpke.seal(&receiver_pub_key, info, Some(associated_data), plaintext).unwrap();
        assert_eq!(
            plaintext.as_ref(),
            hpke.open(&ct, &receiver_priv_key, info, Some(associated_data)).unwrap(),
        );
    }

    #[test]
    fn hpke_context_seal_open() {
        let hpke = Hpke::new(CipherSuite::CURVE25519_AES128);

        // https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.1
        let receiver_pub_key = HpkePublicKey::from(
            decode_hex::<32>("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
                .to_vec(),
        );
        let receiver_priv_key = HpkeSecretKey::from(
            decode_hex::<32>("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
                .to_vec()
        );

        let info = b"some_info";
        let plaintext = b"plaintext";
        let associated_data = b"some_ad";

        let (enc, mut sender_ctx) = hpke.setup_sender(&receiver_pub_key, info).unwrap();
        let mut receiver_ctx = hpke.setup_receiver(&enc, &receiver_priv_key, info).unwrap();
        let ct = sender_ctx.seal(Some(associated_data), plaintext).unwrap();
        assert_eq!(
            plaintext.as_ref(),
            receiver_ctx.open(Some(associated_data), &ct).unwrap(),
        );
    }

#[test]
    fn hpke_context_seal_open_multithreaded() {
        let hpke = Hpke::new(CipherSuite::CURVE25519_AES128);

        // https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.1
        let receiver_pub_key = HpkePublicKey::from(
            decode_hex::<32>("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
                .to_vec(),
        );
        let receiver_priv_key = HpkeSecretKey::from(
            decode_hex::<32>("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
                .to_vec()
        );

        let info = b"some_info";
        let plaintext = b"plaintext";
        let associated_data = b"some_ad";

        let (enc, mut sender_ctx) = hpke.setup_sender(&receiver_pub_key, info).unwrap();
        let mut receiver_ctx = hpke.setup_receiver(&enc, &receiver_priv_key, info).unwrap();

        let pool = thread::spawn(move || {
            for _i in 1..100 {
                let ct = sender_ctx.seal(Some(associated_data), plaintext).unwrap();
                assert_eq!(
                    plaintext.as_ref(),
                    receiver_ctx.open(Some(associated_data), &ct).unwrap(),
                );
            }
        });
        pool.join().unwrap();
    }

    #[test]
    fn hpke_context_export() {
        let hpke = Hpke::new(CipherSuite::CURVE25519_AES128);

        // https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.1
        let receiver_pub_key = HpkePublicKey::from(
            decode_hex::<32>("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
                .to_vec(),
        );
        let receiver_priv_key = HpkeSecretKey::from(
            decode_hex::<32>("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
                .to_vec()
        );

        let info = b"some_info";
        let exporter_ctx = b"export_ctx";

        let (enc, sender_ctx) = hpke.setup_sender(&receiver_pub_key, info).unwrap();
        let receiver_ctx = hpke.setup_receiver(&enc, &receiver_priv_key, info).unwrap();
        assert_eq!(
            sender_ctx.export(exporter_ctx, 32).unwrap(),
            receiver_ctx.export(exporter_ctx, 32).unwrap(),
        );
    }
}
