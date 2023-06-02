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

use crate::aead::AeadType::{Aes128Gcm, Aes256Gcm};
use crate::aead::{Aead, AeadError, AeadImpl};

/// AES-GCM implementation.
pub struct AesGcm(AeadImpl<12, 16>);

/// Instantiates a new AES-128-GCM instance from key material.
pub fn new_aes_128_gcm(key: &[u8; 16]) -> AesGcm {
    AesGcm(AeadImpl::new(key, Aes128Gcm))
}

/// Instantiates a new AES-256-GCM instance from key material.
pub fn new_aes_256_gcm(key: &[u8; 32]) -> AesGcm {
    AesGcm(AeadImpl::new(key, Aes256Gcm))
}

impl Aead<12> for AesGcm {
    const TAG_SIZE: usize = 16;

    fn encrypt(&self, msg: &mut Vec<u8>, aad: &[u8], nonce: &[u8; 12]) -> Result<(), AeadError> {
        self.0.encrypt(msg, aad, nonce)
    }

    fn decrypt(&self, msg: &mut Vec<u8>, aad: &[u8], nonce: &[u8; 12]) -> Result<(), AeadError> {
        self.0.decrypt(msg, aad, nonce)
    }
}

#[cfg(test)]
mod test {
    use crate::aead::aes_gcm::{new_aes_128_gcm, new_aes_256_gcm};
    use crate::aead::Aead;
    use crate::test_helpers::decode_hex;

    #[test]
    fn aes_128_gcm_tests() {
        // TC 1 from crypto/cipher_extra/test/aes_128_gcm_tests.txt
        let key = decode_hex("d480429666d48b400633921c5407d1d1");
        let nonce = decode_hex("3388c676dc754acfa66e172a");
        let tag: [u8; 16] = decode_hex("7d7daf44850921a34e636b01adeb104f");
        let mut buf = Vec::from(&[] as &[u8]);
        let aes = new_aes_128_gcm(&key);
        let result = aes.encrypt(&mut buf, b"", &nonce);
        assert!(result.is_ok());
        assert_eq!(buf, &tag);

        // TC2
        let key = decode_hex("3881e7be1bb3bbcaff20bdb78e5d1b67");
        let nonce = decode_hex("dcf5b7ae2d7552e2297fcfa9");
        let msg: [u8; 5] = decode_hex("0a2714aa7d");
        let ad: [u8; 5] = decode_hex("c60c64bbf7");
        let ct: [u8; 5] = decode_hex("5626f96ecb");
        let tag: [u8; 16] = decode_hex("ff4c4f1d92b0abb1d0820833d9eb83c7");

        let mut buf = Vec::from(msg.as_slice());
        let aes = new_aes_128_gcm(&key);
        let result = aes.encrypt(&mut buf, &ad, &nonce);
        assert!(result.is_ok());
        assert_eq!(&buf[..5], &ct);
        assert_eq!(&buf[5..], &tag);
        let result = aes.decrypt(&mut buf, &ad, &nonce);
        assert!(result.is_ok());
        assert_eq!(buf, &msg);
    }

    #[test]
    fn aes_256_gcm_tests() {
        // TC 1 from crypto/cipher_extra/test/aes_256_gcm_tests.txt
        let key = decode_hex("e5ac4a32c67e425ac4b143c83c6f161312a97d88d634afdf9f4da5bd35223f01");
        let nonce = decode_hex("5bf11a0951f0bfc7ea5c9e58");
        let tag: [u8; 16] = decode_hex("d7cba289d6d19a5af45dc13857016bac");
        let mut buf = Vec::from(&[] as &[u8]);
        let aes = new_aes_256_gcm(&key);
        let result = aes.encrypt(&mut buf, b"", &nonce);
        assert!(result.is_ok());
        assert_eq!(buf, &tag);

        // TC2
        let key = decode_hex("73ad7bbbbc640c845a150f67d058b279849370cd2c1f3c67c4dd6c869213e13a");
        let nonce = decode_hex("a330a184fc245812f4820caa");
        let msg: [u8; 5] = decode_hex("f0535fe211");
        let ad: [u8; 5] = decode_hex("e91428be04");
        let ct: [u8; 5] = decode_hex("e9b8a896da");
        let tag: [u8; 16] = decode_hex("9115ed79f26a030c14947b3e454db9e7");

        let mut buf = Vec::from(msg.as_slice());
        let aes = new_aes_256_gcm(&key);
        let result = aes.encrypt(&mut buf, &ad, &nonce);
        assert!(result.is_ok());
        assert_eq!(&buf[..5], &ct);
        assert_eq!(&buf[5..], &tag);
        let result = aes.decrypt(&mut buf, &ad, &nonce);
        assert!(result.is_ok());
        assert_eq!(buf, &msg);
    }
}
