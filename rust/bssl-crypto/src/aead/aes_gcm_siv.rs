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

use crate::aead::AeadType::{Aes128GcmSiv, Aes256GcmSiv};
use crate::aead::{Aead, AeadError, AeadImpl};

/// AES-GCM-SIV implementation.
pub struct AesGcmSiv(AeadImpl<12, 16>);

/// Instantiates a new AES-128-GCM-SIV instance from key material.
pub fn new_aes_128_gcm_siv(key: &[u8; 16]) -> AesGcmSiv {
    AesGcmSiv(AeadImpl::new(key, Aes128GcmSiv))
}

/// Instantiates a new AES-256-GCM-SIV instance from key material.
pub fn new_aes_256_gcm_siv(key: &[u8; 32]) -> AesGcmSiv {
    AesGcmSiv(AeadImpl::new(key, Aes256GcmSiv))
}

impl Aead<12> for AesGcmSiv {
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
    use crate::aead::{
        aes_gcm_siv::{new_aes_128_gcm_siv, new_aes_256_gcm_siv},
        Aead,
    };
    use crate::test_helpers::decode_hex;

    #[test]
    fn aes_128_gcm_siv_tests() {
        // https://github.com/google/wycheproof/blob/master/testvectors/aes_gcm_siv_test.json
        // TC1 - Empty Message
        let key = decode_hex("01000000000000000000000000000000");
        let nonce = decode_hex("030000000000000000000000");
        let tag: [u8; 16] = decode_hex("dc20e2d83f25705bb49e439eca56de25");
        let mut buf = Vec::from(&[] as &[u8]);
        let aes = new_aes_128_gcm_siv(&key);
        let result = aes.encrypt(&mut buf, b"", &nonce);
        assert!(result.is_ok());
        assert_eq!(buf, &tag);

        // TC2
        let msg: [u8; 8] = decode_hex("0100000000000000");
        let ct: [u8; 8] = decode_hex("b5d839330ac7b786");
        let tag: [u8; 16] = decode_hex("578782fff6013b815b287c22493a364c");
        let mut buf = Vec::from(msg.as_slice());
        let result = aes.encrypt(&mut buf, b"", &nonce);
        assert!(result.is_ok());
        assert_eq!(&buf[..8], &ct);
        assert_eq!(&buf[8..], &tag);
        let result = aes.decrypt(&mut buf, b"", &nonce);
        assert!(result.is_ok());
        assert_eq!(buf, &msg);
    }

    #[test]
    fn aes_256_gcm_siv_tests() {
        // https://github.com/google/wycheproof/blob/master/testvectors/aes_gcm_siv_test.json
        // TC77
        let test_key =
            decode_hex("0100000000000000000000000000000000000000000000000000000000000000");
        let nonce = decode_hex("030000000000000000000000");
        let aes = new_aes_256_gcm_siv(&test_key);
        let msg: [u8; 8] = decode_hex("0100000000000000");
        let mut buf = Vec::new();
        buf.extend_from_slice(&msg);
        let ct: [u8; 8] = decode_hex("c2ef328e5c71c83b");
        let tag: [u8; 16] = decode_hex("843122130f7364b761e0b97427e3df28");
        assert!(aes.encrypt(&mut buf, b"", &nonce).is_ok());
        assert_eq!(&buf[..8], &ct);
        assert_eq!(&buf[8..], &tag);
        assert!(aes.decrypt(&mut buf, b"", &nonce).is_ok());
        assert_eq!(&buf[..], &msg);

        // TC78
        let msg: [u8; 12] = decode_hex("010000000000000000000000");
        let ct: [u8; 12] = decode_hex("9aab2aeb3faa0a34aea8e2b1");
        let tag: [u8; 16] = decode_hex("8ca50da9ae6559e48fd10f6e5c9ca17e");
        let mut buf = Vec::from(msg.as_slice());
        assert!(aes.encrypt(&mut buf, b"", &nonce).is_ok());
        assert_eq!(&buf[..12], &ct);
        assert_eq!(&buf[12..], &tag);
        assert!(aes.decrypt(&mut buf, b"", &nonce).is_ok());
        assert_eq!(&buf[..], &msg);
    }
}
