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

use bssl_crypto::hkdf::{HkdfSha256, HkdfSha512, Salt, Prk};
use bssl_crypto::digest;
use mls_rs_core::crypto::CipherSuite;
use mls_rs_core::error::IntoAnyError;
use mls_rs_crypto_traits::{KdfId, KdfType};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KdfError {
    #[error("the provided length of the key {0} is shorter than the minimum length {1}")]
    TooShortKey(usize, usize),
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

impl IntoAnyError for KdfError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

#[derive(Clone)]
pub struct Kdf(KdfId);

impl Kdf {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        KdfId::new(cipher_suite).map(Self)
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl KdfType for Kdf {
    type Error = KdfError;

    async fn extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, KdfError> {
        if ikm.is_empty() {
            return Err(KdfError::TooShortKey(0, 1));
        }

        let salt = if salt.is_empty() { Salt::None } else { Salt::NonEmpty(salt) };

        match self.0 {
            KdfId::HkdfSha256 => Ok(HkdfSha256::extract(ikm, salt).as_bytes().to_vec()),
            KdfId::HkdfSha512 => Ok(HkdfSha512::extract(ikm, salt).as_bytes()[0..self.extract_size()].to_vec()),
            _ => Err(KdfError::UnsupportedCipherSuite),
        }
    }

    async fn expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, KdfError> {
        if prk.len() < self.extract_size() {
            return Err(KdfError::TooShortKey(prk.len(), self.extract_size()));
        }

        match self.0 {
            KdfId::HkdfSha256 => {
                let hkdf = Prk::new::<digest::Sha256>(
                    prk, self.extract_size());
                match hkdf {
                    Some(x) => Ok(x.expand::<255>(info)[0..len].to_vec()),
                    None => Err(KdfError::TooShortKey(prk.len(), self.extract_size())),
                }
            },
            KdfId::HkdfSha512 => {
                let hkdf = Prk::new::<digest::Sha512>(
                    prk, self.extract_size());
                match hkdf {
                    Some(x) => Ok(x.expand::<255>(info)[0..len].to_vec()),
                    None => Err(KdfError::TooShortKey(prk.len(), self.extract_size())),
                }
            },
            _ => Err(KdfError::UnsupportedCipherSuite),
        }
    }

    fn extract_size(&self) -> usize {
        self.0.extract_size()
    }

    fn kdf_id(&self) -> u16 {
        self.0 as u16
    }
}

#[cfg(all(not(mls_build_async), test))]
mod test {
    use mls_rs_core::crypto::CipherSuite;

    use super::{KdfType, Kdf, KdfError};

    use crate::test_helpers::decode_hex;
    use assert_matches::assert_matches;

    #[test]
    fn sha256() {
        // https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.1
        let ikm : [u8; 22] = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt : [u8; 13] = decode_hex("000102030405060708090a0b0c");
        let info : [u8; 10] = decode_hex("f0f1f2f3f4f5f6f7f8f9");
        let expected_prk : [u8; 32] = decode_hex(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let expected_okm : [u8; 42] = decode_hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );

        let kdf = Kdf::new(CipherSuite::CURVE25519_AES128).unwrap();
        let prk = kdf.extract(&salt, &ikm).unwrap();
        assert_eq!(prk, expected_prk);
        assert_eq!(kdf.expand(&prk, &info, 42).unwrap(), expected_okm);
    }

    #[test]
    fn sha512() {
        // https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/hkdf_sha512_test.json#L141
        let ikm : [u8; 16] = decode_hex("5d3db20e8238a90b62a600fa57fdb318");
        let salt : [u8; 16] = decode_hex("1d6f3b38a1e607b5e6bcd4af1800a9d3");
        let info : [u8; 20] = decode_hex("2bc5f39032b6fc87da69ba8711ce735b169646fd");
        let expected_okm : [u8; 42] = decode_hex(
            "8c3cf7122dcb5eb7efaf02718f1faf70bca20dcb75070e9d0871a413a6c05fc195a75aa9ffc349d70aae",
        );

        let kdf = Kdf::new(CipherSuite::CURVE448_CHACHA).unwrap();
        let prk = kdf.extract(&salt, &ikm).unwrap();
        assert_eq!(kdf.expand(&prk, &info, 42).unwrap(), expected_okm);
    }

    #[test]
    fn unsupported_cipher_suites() {
        let ikm : [u8; 22] = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt : [u8; 13] = decode_hex("000102030405060708090a0b0c");
        
        assert_matches!(
            Kdf::new(CipherSuite::P384_AES256).unwrap().extract(&salt, &ikm),
            Err(KdfError::UnsupportedCipherSuite)
        );
    }
}
