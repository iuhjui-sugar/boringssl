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
use crate::digest::{Sha256, Sha512};
use crate::{digest::Md, PanicResultHandler};
use core::marker::PhantomData;
use foreign_types::ForeignTypeRef;

/// Implementation of HKDF-SHA-256
pub type HkdfSha256 = Hkdf<Sha256>;

/// Implementation of HKDF-SHA-512
pub type HkdfSha512 = Hkdf<Sha512>;

/// Error type returned from the hkdf expand operations when the output key material has
/// an invalid length
#[derive(Debug)]
pub struct InvalidLength;

/// Implementation of hkdf operations which are generic over a provided hashing functions. Type
/// aliases are provided above for convenience of commonly used hashes
pub struct Hkdf<M: Md> {
    salt: Option<Vec<u8>>,
    ikm: Vec<u8>,
    _marker: PhantomData<M>,
}

impl<M: Md> Hkdf<M> {
    /// Creates a new instance of an hkdf from a salt and key material
    pub fn new(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        Self {
            salt: salt.map(Vec::from),
            ikm: Vec::from(ikm),
            _marker: PhantomData::default(),
        }
    }

    /// The RFC5869 HKDF-Expand operation. The info argument for the expand is set to
    /// the concatenation of all the elements of info_components. Returns InvalidLength if the
    /// output is too large or panics if there is an allocation failure
    pub fn expand_multi_info(
        &self,
        info_components: &[&[u8]],
        okm: &mut [u8],
    ) -> Result<(), InvalidLength> {
        self.expand(&info_components.concat(), okm)
    }

    /// The RFC5869 HKDF-Expand operation. Returns InvalidLength if the output is too large, or
    /// panics if there is an allocation failure
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), InvalidLength> {
        // extract the salt bytes from the option, or empty slice if option is None
        let salt = self.salt.as_deref().unwrap_or_default();

        //validate the output size
        (okm.len() <= M::output_size() * 255)
            .then(|| {
                // Safety:
                // - We validate the output length above, so invalid length errors will never be hit
                // which leaves allocation failures as the only possible error case, in which case
                // we panic immediately
                unsafe {
                    bssl_sys::HKDF(
                        okm.as_mut_ptr(),
                        okm.len(),
                        M::get_md().as_ptr(),
                        self.ikm.as_slice().as_ptr(),
                        self.ikm.as_slice().len(),
                        salt.as_ptr(),
                        salt.len(),
                        info.as_ptr(),
                        info.len(),
                    )
                }
                .panic_if_error()
            })
            .ok_or(InvalidLength)
    }
}

#[cfg(test)]
mod tests {
    use crate::digest::{Md, Sha256, Sha512};
    use crate::hkdf::{Hkdf, HkdfSha256};
    use core::iter;
    use hex_literal::hex;

    struct Test<'a> {
        ikm: &'a [u8],
        salt: &'a [u8],
        info: &'a [u8],
        okm: &'a [u8],
    }

    #[test]
    fn hkdf_sha_256_test() {
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");

        let hk = HkdfSha256::new(Some(&salt[..]), &ikm);
        let mut okm = [0u8; 42];
        hk.expand(&info, &mut okm)
            .expect("42 is a valid length for Sha256 to output");

        let expected = hex!(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        assert_eq!(okm, expected);
    }

    // Test Vectors from https://tools.ietf.org/html/rfc5869.
    #[test]
    fn test_rfc5869_sha256() {
        let tests = [
            Test {
                // Test Case 1
                ikm: &hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                salt: &hex!("000102030405060708090a0b0c"),
                info: &hex!("f0f1f2f3f4f5f6f7f8f9"),
                okm: &hex!(
                    "
                    3cb25f25faacd57a90434f64d0362f2a
                    2d2d0a90cf1a5a4c5db02d56ecc4c5bf
                    34007208d5b887185865
                "
                ),
            },
            Test {
                // Test Case 2
                ikm: &hex!(
                    "
                    000102030405060708090a0b0c0d0e0f
                    101112131415161718191a1b1c1d1e1f
                    202122232425262728292a2b2c2d2e2f
                    303132333435363738393a3b3c3d3e3f
                    404142434445464748494a4b4c4d4e4f
                "
                ),
                salt: &hex!(
                    "
                    606162636465666768696a6b6c6d6e6f
                    707172737475767778797a7b7c7d7e7f
                    808182838485868788898a8b8c8d8e8f
                    909192939495969798999a9b9c9d9e9f
                    a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
                "
                ),
                info: &hex!(
                    "
                    b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
                    c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
                    d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
                    e0e1e2e3e4e5e6e7e8e9eaebecedeeef
                    f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
                "
                ),
                okm: &hex!(
                    "
                    b11e398dc80327a1c8e7f78c596a4934
                    4f012eda2d4efad8a050cc4c19afa97c
                    59045a99cac7827271cb41c65e590e09
                    da3275600c2f09b8367793a9aca3db71
                    cc30c58179ec3e87c14c01d5c1f3434f
                    1d87
                "
                ),
            },
            Test {
                // Test Case 3
                ikm: &hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                salt: &hex!(""),
                info: &hex!(""),
                okm: &hex!(
                    "
                    8da4e775a563c18f715f802a063c5a31
                    b8a11f5c5ee1879ec3454e5f3c738d2d
                    9d201395faa4b61a96c8
                "
                ),
            },
        ];
        for Test {
            ikm,
            salt,
            info,
            okm,
        } in tests.iter()
        {
            let salt = if salt.is_empty() {
                None
            } else {
                Some(&salt[..])
            };
            let hkdf = HkdfSha256::new(salt, ikm);
            let mut okm2 = vec![0u8; okm.len()];
            assert!(hkdf.expand(&info[..], &mut okm2).is_ok());
            assert_eq!(okm2[..], okm[..]);
        }
    }

    const MAX_SHA256_LENGTH: usize = 255 * (256 / 8); // =8160

    #[test]
    fn test_lengths() {
        let hkdf = HkdfSha256::new(None, &[]);
        let mut longest = vec![0u8; MAX_SHA256_LENGTH];
        assert!(hkdf.expand(&[], &mut longest).is_ok());
        // Runtime is O(length), so exhaustively testing all legal lengths
        // would take too long (at least without --release). Only test a
        // subset: the first 500, the last 10, and every 100th in between.
        // 0 is an invalid key length for openssl, so start at 1
        let lengths = (1..MAX_SHA256_LENGTH + 1)
            .filter(|&len| !(500..=MAX_SHA256_LENGTH - 10).contains(&len) || len % 100 == 0);

        for length in lengths {
            let mut okm = vec![0u8; length];

            assert!(hkdf.expand(&[], &mut okm).is_ok());
            assert_eq!(okm.len(), length);
            assert_eq!(okm[..], longest[..length]);
        }
    }

    #[test]
    fn test_max_length() {
        let hkdf = HkdfSha256::new(Some(&[]), &[]);
        let mut okm = vec![0u8; MAX_SHA256_LENGTH];
        assert!(hkdf.expand(&[], &mut okm).is_ok());
    }

    #[test]
    fn test_max_length_exceeded() {
        let hkdf = HkdfSha256::new(Some(&[]), &[]);
        let mut okm = vec![0u8; MAX_SHA256_LENGTH + 1];
        assert!(hkdf.expand(&[], &mut okm).is_err());
    }

    #[test]
    fn test_unsupported_length() {
        let hkdf = HkdfSha256::new(Some(&[]), &[]);
        let mut okm = vec![0u8; 90000];
        assert!(hkdf.expand(&[], &mut okm).is_err());
    }

    #[test]
    fn test_expand_multi_info() {
        let info_components = &[
            &b"09090909090909090909090909090909090909090909"[..],
            &b"8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a"[..],
            &b"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"[..],
            &b"4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4"[..],
            &b"1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d"[..],
        ];

        let hkdf = HkdfSha256::new(None, b"some ikm here");

        // Compute HKDF-Expand on the concatenation of all the info components
        let mut oneshot_res = [0u8; 16];
        hkdf.expand(&info_components.concat(), &mut oneshot_res)
            .unwrap();

        // Now iteratively join the components of info_components until it's all 1 component. The value
        // of HKDF-Expand should be the same throughout
        let mut num_concatted = 0;
        let mut info_head = Vec::new();

        while num_concatted < info_components.len() {
            info_head.extend(info_components[num_concatted]);

            // Build the new input to be the info head followed by the remaining components
            let input: Vec<&[u8]> = iter::once(info_head.as_slice())
                .chain(info_components.iter().cloned().skip(num_concatted + 1))
                .collect();

            // Compute and compare to the one-shot answer
            let mut multipart_res = [0u8; 16];
            hkdf.expand_multi_info(&input, &mut multipart_res).unwrap();
            assert_eq!(multipart_res, oneshot_res);
            num_concatted += 1;
        }
    }

    #[test]
    fn run_hkdf_sha_256_wycheproof_test_vectors() {
        run_hkdf_test_vectors::<Sha256>(HashAlg::Sha256)
    }

    #[test]
    fn run_hkdf_sha_512_wycheproof_test_vectors() {
        run_hkdf_test_vectors::<Sha512>(HashAlg::Sha512)
    }

    enum HashAlg {
        Sha256,
        Sha512,
    }

    fn run_hkdf_test_vectors<M: Md>(hash: HashAlg) {
        let test_name = match hash {
            HashAlg::Sha256 => wycheproof::hkdf::TestName::HkdfSha256,
            HashAlg::Sha512 => wycheproof::hkdf::TestName::HkdfSha512,
        };

        let test_set =
            wycheproof::hkdf::TestSet::load(test_name).expect("should be able to load test set");

        for test_group in test_set.test_groups {
            for test in test_group.tests {
                let ikm = test.ikm;
                let salt = test.salt;
                let info = test.info;
                let okm = test.okm;
                let tc_id = test.tc_id;
                if let Some(desc) = run_test::<M>(
                    ikm.as_slice(),
                    salt.as_slice(),
                    info.as_slice(),
                    okm.as_slice(),
                ) {
                    panic!(
                        "\n\
                         Failed test {tc_id}: {desc}\n\
                         ikm:\t{ikm:?}\n\
                         salt:\t{salt:?}\n\
                         info:\t{info:?}\n\
                         okm:\t{okm:?}\n"
                    );
                }
            }
        }
    }

    fn run_test<M: Md>(ikm: &[u8], salt: &[u8], info: &[u8], okm: &[u8]) -> Option<&'static str> {
        let prk = Hkdf::<M>::new(Some(salt), ikm);
        let mut got_okm = vec![0; okm.len()];

        if prk.expand(info, &mut got_okm).is_err() {
            return Some("prk expand");
        }
        if got_okm != okm {
            return Some("mismatch in okm");
        }
        None
    }
}
