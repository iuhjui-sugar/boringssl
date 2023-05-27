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

use crate::CSliceMut;

// TODO: Are there constants in bssl_sys to use?
///
pub const SHARED_KEY_LEN: usize = 32;

/// TODO
pub struct EphemeralSecret {
    eckey: EcKey,
}

// TODO: Check whether this is kosher
unsafe impl Send for EphemeralSecret {}

struct EcKey {
    ptr: *mut bssl_sys::EC_KEY,
}

impl core::fmt::Debug for EcKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcKey").field("ptr", &self.ptr).finish()
    }
}

impl EcKey {
    fn new_by_curve_name(nid: i32) -> Self {
        let eckey = unsafe { bssl_sys::EC_KEY_new_by_curve_name(nid) };
        assert!(!eckey.is_null());
        EcKey { ptr: eckey }
    }
}

impl Drop for EcKey {
    fn drop(&mut self) {
        // Safety: `self.ptr` is owned by this struct
        unsafe { bssl_sys::EC_KEY_free(self.ptr) }
    }
}

struct Pkey {
    ptr: *mut bssl_sys::EVP_PKEY,
}

impl From<&EcKey> for Pkey {
    fn from(eckey: &EcKey) -> Self {
        // Safety: EVP_PKEY_new does not have any preconditions
        let pkey = unsafe { bssl_sys::EVP_PKEY_new() };
        assert!(!pkey.is_null());
        // Safety:
        // - pkey is just allocated and is null-checked
        // - EcKey ensures eckey.ptr is valid during its lifetime
        // - EVP_PKEY_set1_EC_KEY takes a reference, does not take ownership of eckey.ptr
        let result = unsafe { bssl_sys::EVP_PKEY_set1_EC_KEY(pkey, eckey.ptr) };
        assert_eq!(result, 1, "bssl_sys::EVP_PKEY_set1_EC_KEY failed");
        Self { ptr: pkey }
    }
}

impl Drop for Pkey {
    fn drop(&mut self) {
        // Safety: `self.ptr` is owned by this struct
        unsafe { bssl_sys::EVP_PKEY_free(self.ptr) }
    }
}

struct PkeyCtx {
    ptr: *mut bssl_sys::EVP_PKEY_CTX,
}

impl PkeyCtx {
    fn new(pkey: &Pkey) -> Self {
        let pkeyctx = unsafe { bssl_sys::EVP_PKEY_CTX_new(pkey.ptr, core::ptr::null_mut()) };
        assert!(!pkeyctx.is_null());
        Self { ptr: pkeyctx }
    }
}

impl Drop for PkeyCtx {
    fn drop(&mut self) {
        // Safety: self.ptr is owned by this struct
        unsafe { bssl_sys::EVP_PKEY_CTX_free(self.ptr) }
    }
}

impl EphemeralSecret {
    ///
    /// # Panics
    pub fn diffie_hellman(self, other_public_key: &PublicKey) -> SharedSecret {
        let pkey = (&self.eckey).into();

        let pkeyctx = PkeyCtx::new(&pkey);
        let result = unsafe { bssl_sys::EVP_PKEY_derive_init(pkeyctx.ptr) };
        assert_eq!(result, 1, "bssl_sys::EVP_PKEY_derive_init failed");

        let result = unsafe {
            let peer_key: Pkey = (&other_public_key.eckey).into();
            bssl_sys::EVP_PKEY_derive_set_peer(pkeyctx.ptr, peer_key.ptr)
        };
        assert_eq!(result, 1, "bssl_sys::EVP_PKEY_derive_set_peer failed");

        let mut shared_secret = [0_u8; SHARED_KEY_LEN];
        let mut c_slice_mut = CSliceMut(&mut shared_secret);
        let mut keylen = SHARED_KEY_LEN;
        let result = unsafe {
            bssl_sys::EVP_PKEY_derive(pkeyctx.ptr, c_slice_mut.as_mut_ptr(), &mut keylen)
        };
        assert_eq!(result, 1, "bssl_sys::EVP_PKEY_derive failed");

        assert_eq!(
            c_slice_mut.len(),
            keylen,
            "keylen should not be modified since we passed in a non-null key"
        );
        SharedSecret(shared_secret)
    }

    ///
    pub fn generate() -> Self {
        // TODO: Missing safety comments
        let eckey = EcKey::new_by_curve_name(bssl_sys::NID_X9_62_prime256v1);
        let result = unsafe { bssl_sys::EC_KEY_generate_key(eckey.ptr) };
        assert_eq!(result, 1, "bssl_sys::EC_KEY_generate_key failed");

        Self { eckey }
    }

    // Q: In our module we only use it for testing. In the docs for x25519_dalek::EphemeralSecret,
    //    it sounds like part of the safety comes from the inability to create one of these keys
    //    from anything other than randomness. Do we need to tag this method as for-testing-only?
    ///
    // FIXME: Size of private_key_bytes should be constrained, or runtime errored with
    // try_from_private_bytes
    pub fn from_private_bytes(private_key_bytes: &[u8], public_key: &PublicKey) -> Self {
        let private_key_bn = unsafe {
            BigNum::from_raw(bssl_sys::BN_bin2bn(
                private_key_bytes.as_ptr(),
                private_key_bytes.len(),
                core::ptr::null_mut(),
            ))
        };
        let eckey = EcKey::new_by_curve_name(bssl_sys::NID_X9_62_prime256v1);
        let result = unsafe { bssl_sys::EC_KEY_set_private_key(eckey.ptr, private_key_bn.ptr) };
        assert_eq!(result, 1, "bssl_sys::EC_KEY_set_private_key failed");
        let public_ec_point = unsafe { bssl_sys::EC_KEY_get0_public_key(public_key.eckey.ptr) };
        let result = unsafe { bssl_sys::EC_KEY_set_public_key(eckey.ptr, public_ec_point) };
        assert_eq!(result, 1, "bssl_sys::EC_KEY_set_public_key failed");

        Self { eckey }
    }
}

struct BigNum {
    ptr: *mut bssl_sys::BIGNUM,
}

impl BigNum {
    fn new() -> Self {
        // Safety: There are no preconditions for BN_new()
        Self::from_raw(unsafe { bssl_sys::BN_new() })
    }

    fn from_raw(ptr: *mut bssl_sys::BIGNUM) -> Self {
        assert!(!ptr.is_null());
        Self { ptr }
    }
}

impl From<&[u8]> for BigNum {
    fn from(value: &[u8]) -> Self {
        let ptr =
            unsafe { bssl_sys::BN_bin2bn(value.as_ptr(), value.len(), core::ptr::null_mut()) };
        assert!(!ptr.is_null());
        Self { ptr }
    }
}

impl Drop for BigNum {
    fn drop(&mut self) {
        unsafe { bssl_sys::BN_free(self.ptr) }
    }
}

impl<'a> From<&'a EphemeralSecret> for PublicKey {
    fn from(value: &'a EphemeralSecret) -> Self {
        // Safety:
        // TODO
        let ptr = unsafe { bssl_sys::EC_KEY_dup(value.eckey.ptr) };
        Self {
            eckey: EcKey { ptr },
        }
    }
}

// Naming Q: Use PublicKey or PublicValue?
///
#[derive(Debug)]
pub struct PublicKey {
    eckey: EcKey,
}

impl Eq for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        let result = unsafe {
            bssl_sys::EC_POINT_cmp(
                bssl_sys::EC_KEY_get0_group(self.eckey.ptr),
                bssl_sys::EC_KEY_get0_public_key(self.eckey.ptr),
                bssl_sys::EC_KEY_get0_public_key(other.eckey.ptr),
                core::ptr::null_mut(),
            )
        };
        assert_ne!(result, -1, "bssl_sys::EC_POINT_cmp failed");
        result == 0
    }
}

/// Longest possible byte representation of a P256 public key, which is the uncompressed form
/// containing a 1-byte header and 32-byte x and y coordinates.
const PUBLIC_KEY_MAX_BYTES: usize = 65;

impl PublicKey {
    ///
    pub fn to_vec(&self) -> Vec<u8> {
        let mut result_vec = Vec::<u8>::with_capacity(PUBLIC_KEY_MAX_BYTES);
        let buf_len = unsafe {
            let ecpoint = bssl_sys::EC_KEY_get0_public_key(self.eckey.ptr);
            bssl_sys::EC_POINT_point2oct(
                bssl_sys::EC_KEY_get0_group(self.eckey.ptr),
                ecpoint,
                bssl_sys::EC_KEY_get_conv_form(self.eckey.ptr),
                result_vec.as_mut_ptr(),
                result_vec.capacity(),
                core::ptr::null_mut(),
            )
        };
        assert_ne!(buf_len, 0, "bssl_sys::EC_KEY_key2buf failed");
        // Safety: The length is what EC_POINT_point2oct just told us it filled into the buffer.
        unsafe { result_vec.set_len(buf_len) }
        result_vec
    }

    // FIXME: Proper error types
    ///
    pub fn from_affine_coordinates(x: &[u8; 32], y: &[u8; 32]) -> Result<Self, ()> {
        let bn_x = BigNum::from(&x[..]);
        let bn_y = BigNum::from(&y[..]);

        let eckey = EcKey::new_by_curve_name(bssl_sys::NID_X9_62_prime256v1);
        let result = unsafe {
            bssl_sys::EC_KEY_set_public_key_affine_coordinates(eckey.ptr, bn_x.ptr, bn_y.ptr)
        };
        if result == 1 {
            Ok(Self { eckey })
        } else {
            Err(())
        }
    }

    ///
    pub fn to_affine_coordinates(&self) -> ([u8; 32], [u8; 32]) {
        let ecpoint = unsafe { bssl_sys::EC_KEY_get0_public_key(self.eckey.ptr) };
        let bn_x = BigNum::new();
        let bn_y = BigNum::new();

        let result = unsafe {
            bssl_sys::EC_POINT_get_affine_coordinates(
                bssl_sys::EC_KEY_get0_group(self.eckey.ptr),
                ecpoint,
                bn_x.ptr,
                bn_y.ptr,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(
            result, 1,
            "bssl_sys::EC_POINT_get_affine_coordinates failed"
        );
        let mut x_bytes_uninit = core::mem::MaybeUninit::<[u8; 32]>::uninit();
        let mut y_bytes_uninit = core::mem::MaybeUninit::<[u8; 32]>::uninit();
        // Safety:
        // - bn_x is initialized by EC_POINT_get_affine_coordinates above.
        let result = unsafe {
            bssl_sys::BN_bn2bin_padded(x_bytes_uninit.as_mut_ptr() as *mut _, 32, bn_x.ptr)
        };
        assert_eq!(result, 1, "bssl_sys::BN_bn2bin_padded failed");
        let result = unsafe {
            bssl_sys::BN_bn2bin_padded(y_bytes_uninit.as_mut_ptr() as *mut _, 32, bn_y.ptr)
        };
        assert_eq!(result, 1, "bssl_sys::BN_bn2bin_padded failed");

        unsafe { (x_bytes_uninit.assume_init(), y_bytes_uninit.assume_init()) }
    }
}

// TODO: Check for CSliceMut usage

impl TryFrom<&[u8]> for PublicKey {
    type Error = ();

    #[allow(clippy::panic)]
    fn try_from(value: &[u8]) -> Result<Self, ()> {
        // Safety: No preconditions required for EC_KEY_new_by_curve_name
        let eckey = EcKey::new_by_curve_name(bssl_sys::NID_X9_62_prime256v1);

        // Safety: The input slice `value` is a slice from safe Rust.
        let result = unsafe {
            bssl_sys::EC_KEY_oct2key(
                eckey.ptr,
                value.as_ptr(),
                value.len(),
                core::ptr::null_mut(),
            )
        };
        match result {
            0 => Err(()),
            1 => Ok(Self { eckey }),
            _ => panic!("Unexpected return value {result} from EC_POINT_oct2point"),
        }
    }
}

// Q: Do I need to implement zeroize here?
///
pub struct SharedSecret([u8; SHARED_KEY_LEN]);

impl SharedSecret {
    ///
    pub fn to_bytes(&self) -> [u8; SHARED_KEY_LEN] {
        self.0
    }

    ///
    pub fn as_bytes(&self) -> &[u8; SHARED_KEY_LEN] {
        &self.0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::{
        p256::{EphemeralSecret, PublicKey, SHARED_KEY_LEN},
        test_helpers::decode_hex,
    };

    #[test]
    fn p256_test_diffie_hellman() {
        // From wycheproof ecdh_secp256r1_ecpoint_test.json, tcId 1
        // http://google3/third_party/wycheproof/testvectors/ecdh_secp256r1_ecpoint_test.json;l=22;rcl=375894991
        // sec1 public key manually extracted from the ASN encoded test data
        let public_key_sec1: [u8; 65] = decode_hex(
            "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf"
        );
        let private: [u8; 32] =
            decode_hex("0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346");
        let expected_shared_secret: [u8; SHARED_KEY_LEN] =
            decode_hex("53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285");

        let public_key: PublicKey = (&public_key_sec1[..]).try_into().unwrap();
        let ephemeral_secret = EphemeralSecret::from_private_bytes(&private, &public_key);
        let actual_shared_secret = ephemeral_secret.diffie_hellman(&public_key);

        assert_eq!(actual_shared_secret.0, expected_shared_secret);
    }

    #[test]
    fn generate_diffie_hellman_matches() {
        let ephemeral_secret_1 = EphemeralSecret::generate();
        let ephemeral_secret_2 = EphemeralSecret::generate();
        let public_key_1 = PublicKey::from(&ephemeral_secret_1);
        let public_key_2 = PublicKey::from(&ephemeral_secret_2);

        let diffie_hellman_1 = ephemeral_secret_1.diffie_hellman(&public_key_2);
        let diffie_hellman_2 = ephemeral_secret_2.diffie_hellman(&public_key_1);

        assert_eq!(diffie_hellman_1.to_bytes(), diffie_hellman_2.to_bytes());
    }

    #[test]
    fn affine_coordinates_test() {
        let ephemeral_secret = EphemeralSecret::generate();
        let public_key = PublicKey::from(&ephemeral_secret);

        let (x, y) = public_key.to_affine_coordinates();

        let recreated_public_key = PublicKey::from_affine_coordinates(&x, &y);
        assert_eq!(public_key, recreated_public_key.unwrap());
    }
}
