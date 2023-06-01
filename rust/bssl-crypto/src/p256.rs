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

use crate::{
    ec::EcKey,
    pkey::{Pkey, PkeyCtx},
    CSliceMut, ForeignType,
};

const PRIVATE_KEY_LEN: usize = 32;

/// Ephemeral secret used in a P256 elliptic curve Diffie-Hellman. This represents the generated key
/// pair that should be used in no more than one Diffie-Hellman key exchange.
pub struct EphemeralSecret {
    /// An EcKey containing the private-public key pair
    eckey: EcKey,
}

/// Error type for P256 operations.
#[derive(Debug)]
pub enum Error {
    /// Failed when trying to convert between representations.
    ConversionFailed,
}

impl EphemeralSecret {
    /// Derives a shared secrect from this ephemeral secret and the given public key.
    ///
    /// # Panics
    /// When `OUTPUT_SIZE` is insufficient to store the output of the shared secret.
    #[allow(clippy::expect_used)]
    pub fn diffie_hellman<const OUTPUT_SIZE: usize>(
        self,
        other_public_key: PublicKey,
    ) -> SharedSecret<OUTPUT_SIZE> {
        let pkey: Pkey = self.eckey.into();
        let pkey_ctx = PkeyCtx::new(&pkey);
        let other_pkey: Pkey = other_public_key.eckey.into();
        let mut output = [0_u8; OUTPUT_SIZE];
        pkey_ctx
            .diffie_hellman(&other_pkey, CSliceMut(&mut output))
            .expect("OUTPUT_SIZE should be sufficient to store output secret");
        SharedSecret(output)
    }

    /// Generate a new Ephemeral secret for use in a Diffie-Hellman key exchange.
    pub fn generate() -> Self {
        Self {
            eckey: EcKey::generate(bssl_sys::NID_X9_62_prime256v1),
        }
    }

    /// Tries to convert the given bytes into an ephemeral secret.
    ///
    /// `private_key_bytes` is the octet form that consists of the content octets of the
    /// `privateKey` `OCTET STRING` in an `ECPrivateKey` ASN.1 structure.
    ///
    /// Returns an error if the given bytes is not a valid representation of a P256 private key.
    pub fn from_private_bytes(private_key_bytes: &[u8; PRIVATE_KEY_LEN]) -> Result<Self, Error> {
        EcKey::try_from_raw_bytes(bssl_sys::NID_X9_62_prime256v1, private_key_bytes)
            .map(|eckey| Self { eckey })
            .map_err(|_| Error::ConversionFailed)
    }
}

impl<'a> From<&'a EphemeralSecret> for PublicKey {
    fn from(value: &'a EphemeralSecret) -> Self {
        Self {
            eckey: value.eckey.clone(),
        }
    }
}

/// A public key for NIST P-256 elliptic curve.
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// An EcKey containing the public key
    eckey: EcKey,
}

impl Eq for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.eckey.public_key_eq(&other.eckey)
    }
}

const AFFINE_COORDINATE_SIZE: usize = 32;

impl PublicKey {
    /// Converts this public key to its byte representation.
    pub fn to_vec(&self) -> Vec<u8> {
        self.eckey.to_vec()
    }

    /// Converts the given affine coordinates into a public key.
    pub fn from_affine_coordinates(
        x: &[u8; AFFINE_COORDINATE_SIZE],
        y: &[u8; AFFINE_COORDINATE_SIZE],
    ) -> Result<Self, Error> {
        EcKey::try_new_public_key_from_affine_coordinates(
            bssl_sys::NID_X9_62_prime256v1,
            &x[..],
            &y[..],
        )
        .map(|eckey| Self { eckey })
        .map_err(|_| Error::ConversionFailed)
    }

    /// Converts this public key to its affine coordinates.
    pub fn to_affine_coordinates(
        &self,
    ) -> ([u8; AFFINE_COORDINATE_SIZE], [u8; AFFINE_COORDINATE_SIZE]) {
        let (bn_x, bn_y) = self.eckey.to_affine_coordinates();

        let mut x_bytes_uninit = core::mem::MaybeUninit::<[u8; AFFINE_COORDINATE_SIZE]>::uninit();
        let mut y_bytes_uninit = core::mem::MaybeUninit::<[u8; AFFINE_COORDINATE_SIZE]>::uninit();
        // Safety:
        // - `BigNum` guarantees the validity of its ptr
        // - The size of `x/y_bytes_uninit` and the length passed to `BN_bn2bin_padded` are both
        //   `AFFINE_COORDINATE_SIZE`
        let (result_x, result_y) = unsafe {
            (
                bssl_sys::BN_bn2bin_padded(
                    x_bytes_uninit.as_mut_ptr() as *mut _,
                    AFFINE_COORDINATE_SIZE,
                    bn_x.as_ptr(),
                ),
                bssl_sys::BN_bn2bin_padded(
                    y_bytes_uninit.as_mut_ptr() as *mut _,
                    AFFINE_COORDINATE_SIZE,
                    bn_y.as_ptr(),
                ),
            )
        };
        assert_eq!(result_x, 1, "bssl_sys::BN_bn2bin_padded failed");
        assert_eq!(result_y, 1, "bssl_sys::BN_bn2bin_padded failed");

        // Safety: Fields initialized by `BN_bn2bin_padded` above.
        unsafe { (x_bytes_uninit.assume_init(), y_bytes_uninit.assume_init()) }
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Error> {
        EcKey::try_new_public_key_from_bytes(bssl_sys::NID_X9_62_prime256v1, value)
            .map(|eckey| Self { eckey })
            .map_err(|_| Error::ConversionFailed)
    }
}

/// Shared secret derived from a Diffie-Hellman key exchange. Don't use the shared key directly,
/// rather use a KDF and also include the two public values as inputs.
pub struct SharedSecret<const SIZE: usize>([u8; SIZE]);

impl<const SIZE: usize> SharedSecret<SIZE> {
    /// Gets a copy of the shared secret.
    pub fn to_bytes(&self) -> [u8; SIZE] {
        self.0
    }

    /// Gets a reference to the underlying data in this shared secret.
    pub fn as_bytes(&self) -> &[u8; SIZE] {
        &self.0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::{
        p256::{EphemeralSecret, PublicKey, PRIVATE_KEY_LEN},
        test_helpers::decode_hex,
    };

    #[test]
    fn p256_test_diffie_hellman() {
        // From wycheproof ecdh_secp256r1_ecpoint_test.json, tcId 1
        // sec1 public key manually extracted from the ASN encoded test data
        let public_key_sec1: [u8; 65] = decode_hex(concat!(
            "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f",
            "26ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf",
        ));
        let private: [u8; PRIVATE_KEY_LEN] =
            decode_hex("0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346");
        let expected_shared_secret: [u8; 32] =
            decode_hex("53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285");

        let public_key: PublicKey = (&public_key_sec1[..]).try_into().unwrap();
        let ephemeral_secret = EphemeralSecret::from_private_bytes(&private)
            .expect("Input private key should be valid");
        let actual_shared_secret = ephemeral_secret.diffie_hellman(public_key);

        assert_eq!(actual_shared_secret.0, expected_shared_secret);
    }

    #[test]
    fn generate_diffie_hellman_matches() {
        let ephemeral_secret_1 = EphemeralSecret::generate();
        let ephemeral_secret_2 = EphemeralSecret::generate();
        let public_key_1 = PublicKey::from(&ephemeral_secret_1);
        let public_key_2 = PublicKey::from(&ephemeral_secret_2);

        let diffie_hellman_1 = ephemeral_secret_1.diffie_hellman::<32>(public_key_2);
        let diffie_hellman_2 = ephemeral_secret_2.diffie_hellman::<32>(public_key_1);

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
