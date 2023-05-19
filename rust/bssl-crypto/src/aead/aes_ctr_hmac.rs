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

use crate::aead::AeadType::{Aes128CtrHmacSha256, Aes256CtrHmacSha256};
use crate::aead::{Aead, AeadError, AeadImpl};

/// An AES-CTR-HMAC-SHA256 implementation.
pub struct AesCtrHmacSha256(AeadImpl<12, 32>);

/// Instantiates a new AES-256-CTR-HMAC-SHA256 instance from key material, where the key material is
/// a 16 byte aes key concatenated with a 32 byte hmac key.
pub fn new_aes_128_ctr_hmac_sha256(key: [u8; 48]) -> AesCtrHmacSha256 {
    AesCtrHmacSha256(AeadImpl::new(key, Aes128CtrHmacSha256))
}

/// Instantiates a new AES-256-CTR-HMAC-SHA256 instance from key material, where the key material is
/// a 32 byte aes key concatenated with a 32 byte hmac key.
pub fn new_aes_256_ctr_hmac_sha256(key: [u8; 64]) -> AesCtrHmacSha256 {
    AesCtrHmacSha256(AeadImpl::new(key, Aes256CtrHmacSha256))
}

impl Aead<12> for AesCtrHmacSha256 {
    const TAG_SIZE: usize = 32;

    fn encrypt(&self, msg: &mut Vec<u8>, aad: &[u8], nonce: &[u8; 12]) -> Result<(), AeadError> {
        self.0.encrypt(msg, aad, nonce)
    }

    fn decrypt(&self, msg: &mut Vec<u8>, aad: &[u8], nonce: &[u8; 12]) -> Result<(), AeadError> {
        self.0.decrypt(msg, aad, nonce)
    }
}

#[cfg(test)]
mod test {
    use crate::aead::aes_ctr_hmac::{new_aes_128_ctr_hmac_sha256, new_aes_256_ctr_hmac_sha256};
    use crate::aead::Aead;
    use crate::test_helpers::decode_hex;

    #[test]
    fn aes_128_ctr_hmac_sha256_test_empty_msg() {
        // TC1 from aes_128_ctr_hmac_sha256.txt
        let key = decode_hex("067b841a2540cb467b75f2188f5da4b5aeb7e0e44582a2b668b5b1ff39e21c4e65745470fb1be1aa909c62fabcf0e6ac");
        let nonce = decode_hex("10e0ecb00da5345127407150");
        let tag: [u8; 32] =
            decode_hex("a82a891565e466957ad5a499d45b579d31acaf582f54d518f8f9c128936dac4c");
        let mut buf = Vec::from(&[] as &[u8]);
        let aes = new_aes_128_ctr_hmac_sha256(key);
        let result = aes.encrypt(&mut buf, b"", &nonce);
        assert!(result.is_ok());
        assert_eq!(buf, &tag);
    }

    #[test]
    fn aes_128_ctr_hmac_sha256_test_empty_msg_with_ad() {
        // TC2 from aes_128_ctr_hmac_sha256.txt
        let key = decode_hex("c9d9ef2c808c3f8b22f659c12147104b08cec2390a84f0c4b887ca4c247c8c9dd45e72f48b30b67a8545750387232344");
        let nonce = decode_hex("58bddf96158a3a588bf3ec05");
        let ad: [u8; 1] = decode_hex("5d");
        let mut buf = Vec::from(&[] as &[u8]);
        let tag: [u8; 32] =
            decode_hex("3580c1601d1c9a5b1595d3dee35b0cd9e1b115d8b0abee557b2c207b8d0df5ee");
        let aes = new_aes_128_ctr_hmac_sha256(key);

        let result = aes.encrypt(&mut buf, &ad, &nonce);
        assert!(result.is_ok());
        assert_eq!(&buf, &tag);
        let result = aes.decrypt(&mut buf, &ad, &nonce);
        assert!(result.is_ok());
        assert_eq!(buf, &[]);
    }

    #[test]
    fn aes_128_ctr_hmac_sha256_test() {
        // Last test case from aes_128_ctr_hmac_sha256.txt
        let key = decode_hex("e7fc36c9fe87a38f9bb4ca67723267e80e16bf39740eb1090234a473d68aed9c96fe2f96e539795eb042276aec5d7505");
        let nonce = decode_hex("83d768746d40dcd695e49ff4");
        let ad: [u8; 128] = decode_hex("59114e9f21b380ae6068609ac36688e6aa7c2533cbfe07013ad1b6663bfa42e39f20e62b45c0faa256c1d33caa9f59b1e30d8502bb7148d051451b3d0265cb9fd0d82e4f4e0489ac606956762d8e7b70abd7eca413ddb708f119c342b3d0d5df673769d8df281656d909b68b6f6438edd60339fd84ff69918b6036ad12a0a588");
        let msg:[u8; 128] = decode_hex("e61f0e02a70249b62ec9a8fdbaf6622c9c6316599daff421f1b19815707b67587d196b7e1452c7d7609f108ea946675ac5d97ed215b92a451aa6a11717ab7819f84848151007f37e2cdc8aa99969c3d5652aeeb65fc21b621865f47f44eb2c528ee1142d11f513761a6bb2d169126503db5b263a410cadd2773ff931a032a885");
        let ct: [u8; 128] = decode_hex("4f12807736c9ab32a2be2e00c9a0236394a8bcfcec6037e7582af462a73bf10aa73bd90e2bc24b97f7001ccf653574aea294bc7b30b77540f475e0e846ab78ffcfa1fef28058e540fea43d9017d4efa05c837611b2eacf0034f26cb7903eff7874973c6da7843892bfc676170a75f839e297dc7f04c74b40f4bda20a45b2a352");
        let mut buf = Vec::from(msg.as_slice());
        let tag: [u8; 32] =
            decode_hex("9b05aab44ba4d1451f14e087be626232ed11c4ed04081f0d4d47ab593fc619b1");
        let aes = new_aes_128_ctr_hmac_sha256(key);

        let result = aes.encrypt(&mut buf, &ad, &nonce);
        assert!(result.is_ok());
        assert_eq!(&buf[..msg.len()], &ct);
        assert_eq!(&buf[msg.len()..], &tag);
        let result = aes.decrypt(&mut buf, &ad, &nonce);
        assert!(result.is_ok());
        assert_eq!(buf, &msg);
    }

    #[test]
    fn aes_256_ctr_hmac_sha256_test_empty_msg() {
        // TC1 from aes_256_ctr_hmac_sha256.txt
        let key = decode_hex("a5060fecb0a738d8ff6dd50009a757c6e58db73228534d03f32c26baa1c209f402c3e03a6947c1d9421d63ce43f6df26d30ce783f5ed0d6b88edd389d9f92d8d");
        let nonce = decode_hex("b52227e92203630a79ec7f5c");
        let tag: [u8; 32] =
            decode_hex("e61a28f5df7061b4236834d2034d2b62cb63c660b7de696c26b345e66b34d222");
        let mut buf = Vec::from(&[] as &[u8]);
        let aes = new_aes_256_ctr_hmac_sha256(key);
        let result = aes.encrypt(&mut buf, b"", &nonce);
        assert!(result.is_ok());
        assert_eq!(buf, &tag);
    }

    #[test]
    fn aes_1256_ctr_hmac_sha256_test_empty_msg_with_ad() {
        // TC2 from aes_256_ctr_hmac_sha256.txt
        let key = decode_hex("d676047046bd5be9263ae39caaa0f688abb1bc67c083658894da6aeeff80b6d58ffc7ca1a1c88f49e629bf5544b2cc7669367202b158fce83fc4a4826dd90a7c");
        let nonce = decode_hex("eabef87a00fd99ebb6ed6d25");
        let ad: [u8; 1] = decode_hex("83");
        let mut buf = Vec::from(&[] as &[u8]);
        let tag: [u8; 32] =
            decode_hex("473cf728899cd5fdd54f18d6f934c3901f7ca118fc5ab2cbb837feefa7852a67");
        let aes = new_aes_256_ctr_hmac_sha256(key);

        let result = aes.encrypt(&mut buf, &ad, &nonce);
        assert!(result.is_ok());
        assert_eq!(&buf, &tag);
        let result = aes.decrypt(&mut buf, &ad, &nonce);
        assert!(result.is_ok());
        assert_eq!(buf, &[]);
    }

    #[test]
    fn aes_256_ctr_hmac_sha256_test() {
        // Last test case from aes_256_ctr_hmac_sha256.txt
        let key = decode_hex("e6fd8144cdb305bf9e62a2c901764c62902f354409d8c5b9c8cbfc0ba8ac7d0859ff8994e573e46784395d89c355a91a313f601b56e86ed3fd10ba428a5481ce");
        let nonce = decode_hex("bae080718d3e5c5998542f15");
        let ad: [u8; 128] = decode_hex("51ae57749b7757718aef9b9c47da5794659516e7f98bc80e6c18c89253f8617963331f54d4f009f087d1d2bd69a083f3a4b98f2a51ce24ffc6079774f7c7b01638b6131bfccebe21fea67bc839c259a50fcc0a16a69ada3c5adee4097d9e053a03266cb9b4b39ee2a465ec1aa058e61a0b9888b93bfcfd103f91ca3a7b274a10");
        let msg:[u8; 128] = decode_hex("2258ffcd6fcf91b1723f8db0047525d61cc8ffc440acf3290690685d16384292493807312b7dfc23ac9d9c3ee1405baab21a3770a05875cfe325268b65fc877463e3208c842ea4a32cf144cc46d57afd91f6b6b5d85fb2dedb0702f0c4e7f742cf4c9b4aec02f07267ec1f7b96a5a3ef25f6c1b4c27bd829e86583e239cd854b");
        let ct: [u8; 128] = decode_hex("5b2fe8eea3313cc04d5ec75d75d05b3242b6e3b65c6fa1761716780c9529ff8ca523096dd037c5bda27984aa93c702ce9c01c63569a90657cc6373ad5d4473028b7eef69dd79c44c38d0063e8a8b7f1aa2bf6b646711ecd4eea3fa27408e089d9c4c4aceedff29a25baa6a9069eb7eac83a53212c0b387d700547c46cdc525e3");
        let mut buf = Vec::from(msg.as_slice());
        let tag: [u8; 32] =
            decode_hex("60319de093aec5c0bb8d5f17e950b0f4df0dfd20ad96490f6f12db461b2a4a84");
        let aes = new_aes_256_ctr_hmac_sha256(key);

        let result = aes.encrypt(&mut buf, &ad, &nonce);
        assert!(result.is_ok());
        assert_eq!(&buf[..msg.len()], &ct);
        assert_eq!(&buf[msg.len()..], &tag);
        let result = aes.decrypt(&mut buf, &ad, &nonce);
        assert!(result.is_ok());
        assert_eq!(buf, &msg);
    }
}
