// /* Copyright (c) 2024, Google Inc.
//  *
//  * Permission to use, copy, modify, and/or distribute this software for any
//  * purpose with or without fee is hereby granted, provided that the above
//  * copyright notice and this permission notice appear in all copies.
//  *
//  * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
//  * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
//  * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
//  * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//  * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
//  * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
//  * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//  */

// use bssl_crypto::hpke;
// use mls_rs_core::crypto::{CipherSuite, HpkeCiphertext, HpkeContextR, HpkeContextS, HpkeModeId, HpkePublicKey, HpkeSecretKey};
// use mls_rs_core::error::IntoAnyError;
// use tokio::sync::Mutex;

// use thiserror::Error;

// #[derive(Debug, Error)]
// pub enum HpkeError {
// 	#[error("BoringSSL error")]
// 	BoringsslError,
//     #[error("unsupported cipher suite")]
//     UnsupportedCipherSuite,
// }

// impl IntoAnyError for HpkeError {
//     fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
//         Ok(self.into())
//     }
// }

// pub struct ContextS(pub Mutex<hpke::SenderContext>);

// #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
// #[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
// #[cfg_attr(
//     all(not(target_arch = "wasm32"), mls_build_async),
//     maybe_async::must_be_async
// )]
// impl HpkeContextS for ContextS {
//     type Error = HpkeError;

//     async fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, Self::Error> {
//         unimplemented!();
//     }

//     unsafe async fn seal(
//     	&mut self,
//     	aad: Option<&[u8]>,
//     	data: &[u8]
//     ) -> Result<Vec<u8>, Self::Error> {
//     	Ok(self.0.lock().await.seal(data, aad.unwrap_or_default()).await)
//     }
// }

// pub struct ContextR(pub Mutex<hpke::RecipientContext>);

// #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
// #[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
// #[cfg_attr(
//     all(not(target_arch = "wasm32"), mls_build_async),
//     maybe_async::must_be_async
// )]
// impl HpkeContextR for ContextR {
//     type Error = HpkeError;

//     // async fn inner(&self) -> MutexGuard<'_, hpke::RecipientContext> {
//     //     self.0.lock().await
//     // }

//     async fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, Self::Error> {
//         unimplemented!();
//     }

//     async fn open(
//         &mut self,
//         aad: Option<&[u8]>,
//         ciphertext: &[u8],
//     ) -> Result<Vec<u8>, Self::Error> {
//     	unimplemented!();
//         // match self.0.lock().open(ciphertext, aad.unwrap_or_default()).await {
//         // 	Some(x) => Ok(x),
//         // 	None => Err(HpkeError::BoringsslError),
//         // }
//     }
// }

// pub struct Hpke(pub CipherSuite);

// impl Hpke {
// 	#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
//     pub async fn setup_sender(
//         &self,
//         remote_key: &HpkePublicKey,
//         info: &[u8],
//     ) -> Result<(Vec<u8>, ContextS), HpkeError> {
//     	let params = Self::cipher_suite_to_params(self.0)?;
//     	match hpke::SenderContext::new(&params, &remote_key, info) {
//     		Some((mut ctx, encapsulated_key)) => Ok((encapsulated_key, ContextS(ctx.into()))),
//     		None => Err(HpkeError::BoringsslError)
//     	}
//     }

//     #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
//     pub async fn seal(
//         &self,
//         remote_key: &HpkePublicKey,
//         info: &[u8],
//         aad: Option<&[u8]>,
//         pt: &[u8],
//     ) -> Result<HpkeCiphertext, HpkeError> {
//     	let (kem_output, mut ctx) = self.setup_sender(remote_key, info).await?;
//     	Ok(HpkeCiphertext {
//     		kem_output,
//     		ciphertext: ctx.seal(aad, pt).await?,
//     	})
//     }

//     #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
//     pub async fn setup_receiver(
//         &self,
//         enc: &[u8],
//         local_secret: &HpkeSecretKey,
//         local_public: &HpkePublicKey,
//         info: &[u8],
//     ) -> Result<ContextR, HpkeError> {
// 		let params = Self::cipher_suite_to_params(self.0)?;
// 		match hpke::RecipientContext::new(&params, &local_secret, &local_public, info) {
//     		Some(mut ctx) => Ok(ContextR(ctx.into())),
//     		None => Err(HpkeError::BoringsslError)
//     	}
//     }

//     #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
//     pub async fn open(
//         &self,
//         ciphertext: &HpkeCiphertext,
//         local_secret: &HpkeSecretKey,
//         local_public: &HpkePublicKey,
//         info: &[u8],
//         aad: Option<&[u8]>,
//     ) -> Result<Vec<u8>, HpkeError> {
//     	let mut ctx = self.setup_receiver(
//     		&ciphertext.kem_output, local_secret, local_public, info).await?;
//     	ctx.open(aad, &ciphertext.ciphertext).await
//     }

//     fn cipher_suite_to_params(cipher_suite: CipherSuite) -> Result<hpke::Params, HpkeError> {
//     	match cipher_suite {
//     		CipherSuite::CURVE25519_AES128 =>
//     			Ok(hpke::Params::new(
//     				hpke::Kem::X25519HkdfSha256,
//     				hpke::Kdf::HkdfSha256,
//     				hpke::Aead::Aes128Gcm,
//     			)),
//             CipherSuite::CURVE25519_CHACHA =>
//             	Ok(hpke::Params::new(
//     				hpke::Kem::X25519HkdfSha256,
//     				hpke::Kdf::HkdfSha256,
//     				hpke::Aead::Chacha20Poly1305,
//     			)),
//             _ => Err(HpkeError::UnsupportedCipherSuite),
//     	}
//     }
// }
