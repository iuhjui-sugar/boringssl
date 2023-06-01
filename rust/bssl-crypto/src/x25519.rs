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

//! X25519 is the Diffie-Hellman primitive built from curve25519. It is sometimes referred to as
//! “curve25519”, but “X25519” is a more precise name. See http://cr.yp.to/ecdh.html and
//! https://tools.ietf.org/html/rfc7748.

/// Number of bytes in a private key in X25519
pub const PRIVATE_KEY_LEN: usize = bssl_sys::X25519_PRIVATE_KEY_LEN as usize;
/// Number of bytes in a public key in X25519
pub const PUBLIC_KEY_LEN: usize = bssl_sys::X25519_PUBLIC_VALUE_LEN as usize;
/// Number of bytes in a shared secret derived with X25519
pub const SHARED_KEY_LEN: usize = bssl_sys::X25519_SHARED_KEY_LEN as usize;

/// Error while performing a X25519 Diffie-Hellman key exchange.
#[derive(Debug)]
pub struct DiffieHellmanError;

/// An ephemeral secret containing a X25519 key pair.
pub struct EphemeralSecret {
    private_key: [u8; PRIVATE_KEY_LEN],
    public_key: [u8; PUBLIC_KEY_LEN],
}

impl EphemeralSecret {
    /// Derives a shared secrect from this ephemeral secret and the given public key.
    pub fn diffie_hellman(
        self,
        other_public_key: &PublicKey,
    ) -> Result<SharedSecret, DiffieHellmanError> {
        let mut shared_key_uninit = core::mem::MaybeUninit::<[u8; SHARED_KEY_LEN]>::uninit();
        // Safety:
        // - private_key and other_public_key are Rust 32-byte arrays
        // - shared_key_uninit is just initialized above to a 32 byte array
        let result = unsafe {
            bssl_sys::X25519(
                shared_key_uninit.as_mut_ptr() as *mut u8,
                self.private_key.as_ptr(),
                other_public_key.0.as_ptr(),
            )
        };
        if result == 1 {
            // Safety:
            // - `shared_key_uninit` is initialized by `X25519` above, and we checked that it
            //   succeeded
            let shared_key = unsafe { shared_key_uninit.assume_init() };
            Ok(SharedSecret(shared_key))
        } else {
            Err(DiffieHellmanError)
        }
    }

    /// Generate a new Ephemeral secret for use in a Diffie-Hellman key exchange.
    pub fn generate() -> Self {
        let mut public_key_uninit = core::mem::MaybeUninit::<[u8; PUBLIC_KEY_LEN]>::uninit();
        let mut private_key_uninit = core::mem::MaybeUninit::<[u8; PRIVATE_KEY_LEN]>::uninit();
        // Safety:
        // - private_key_uninit and public_key_uninit are allocated to 32-bytes
        let (public_key, private_key) = unsafe {
            bssl_sys::X25519_keypair(
                public_key_uninit.as_mut_ptr() as *mut u8,
                private_key_uninit.as_mut_ptr() as *mut u8,
            );
            // Safety: Initialized by `X25519_keypair` above
            (
                public_key_uninit.assume_init(),
                private_key_uninit.assume_init(),
            )
        };
        Self {
            private_key,
            public_key,
        }
    }

    // Q: In our module we only use it for testing. Do we need to tag this method as for-testing-only?

    /// Tries to convert the given bytes into a private key.
    ///
    /// Returns an error if the given bytes is not a valid representation of an X25519 private key.
    pub fn from_private_bytes(private_key_bytes: &[u8; PRIVATE_KEY_LEN]) -> Self {
        let mut public_key_uninit = core::mem::MaybeUninit::<[u8; PUBLIC_KEY_LEN]>::uninit();
        let private_key: [u8; PRIVATE_KEY_LEN] = private_key_bytes.to_owned();
        // Safety:
        // - private_key and public_key are Rust 32-byte arrays
        let public_key = unsafe {
            bssl_sys::X25519_public_from_private(
                public_key_uninit.as_mut_ptr() as *mut _,
                private_key.as_ptr(),
            );
            public_key_uninit.assume_init()
        };
        Self {
            private_key,
            public_key,
        }
    }
}

impl<'a> From<&'a EphemeralSecret> for PublicKey {
    fn from(value: &'a EphemeralSecret) -> Self {
        Self(value.public_key)
    }
}

// Naming Q: Use PublicKey or PublicValue?
/// A public key for X25519 elliptic curve.
#[derive(Debug, PartialEq, Eq)]
pub struct PublicKey([u8; PUBLIC_KEY_LEN]);

impl PublicKey {
    /// Converts this public key to its byte representation.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0
    }

    /// Returns a reference to the byte representation of this public key.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// Shared secret derived from a Diffie-Hellman key exchange. Don't use the shared key directly,
/// rather use a KDF and also include the two public values as inputs.
pub struct SharedSecret([u8; SHARED_KEY_LEN]);

impl SharedSecret {
    /// Gets a copy of the shared secret.
    pub fn to_bytes(&self) -> [u8; SHARED_KEY_LEN] {
        self.0
    }

    /// Gets a reference to the underlying data in this shared secret.
    pub fn as_bytes(&self) -> &[u8; SHARED_KEY_LEN] {
        &self.0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::{
        test_helpers::decode_hex,
        x25519::{EphemeralSecret, PublicKey},
    };

    #[test]
    fn x25519_test_diffie_hellman() {
        // wycheproof/testvectors/x25519_test.json tcId 1
        let public_key_bytes =
            decode_hex("504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829");
        let private_key =
            decode_hex("c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475");
        let expected_shared_secret =
            decode_hex("436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320");
        let public_key = PublicKey(public_key_bytes);
        let ephemeral_secret = EphemeralSecret {
            private_key,
            public_key: [0_u8; 32], // The public key is not used in diffie hellman
        };

        let shared_secret = ephemeral_secret.diffie_hellman(&public_key);
        assert_eq!(expected_shared_secret, shared_secret.unwrap().to_bytes());
    }

    #[test]
    fn x25519_generate_diffie_hellman_matches() {
        let ephemeral_secret_1 = EphemeralSecret::generate();
        let ephemeral_secret_2 = EphemeralSecret::generate();
        let public_key_1 = PublicKey::from(&ephemeral_secret_1);
        let public_key_2 = PublicKey::from(&ephemeral_secret_2);

        let diffie_hellman_1 = ephemeral_secret_1.diffie_hellman(&public_key_2).unwrap();
        let diffie_hellman_2 = ephemeral_secret_2.diffie_hellman(&public_key_1).unwrap();

        assert_eq!(diffie_hellman_1.to_bytes(), diffie_hellman_2.to_bytes());
    }

    #[test]
    fn x25519_test_diffie_hellman_zero_public_key() {
        // wycheproof/testvectors/x25519_test.json tcId 32
        let public_key_bytes =
            decode_hex("0000000000000000000000000000000000000000000000000000000000000000");
        let private_key =
            decode_hex("88227494038f2bb811d47805bcdf04a2ac585ada7f2f23389bfd4658f9ddd45e");
        let public_key = PublicKey(public_key_bytes);
        let ephemeral_secret = EphemeralSecret {
            private_key,
            public_key: [0_u8; 32], // The public key is not used in diffie hellman
        };

        let shared_secret = ephemeral_secret.diffie_hellman(&public_key);
        assert!(shared_secret.is_err());
    }

    #[test]
    fn x25519_public_key_byte_conversion() {
        let public_key_bytes =
            decode_hex("504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829");
        let public_key = PublicKey(public_key_bytes);
        assert_eq!(&public_key_bytes, public_key.as_bytes());
        assert_eq!(public_key_bytes, public_key.to_bytes());
    }

    #[test]
    fn x25519_test_public_key_from_ephemeral_secret() {
        let public_key_bytes =
            decode_hex("504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829");
        let private_key =
            decode_hex("c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475");
        let ephemeral_secret = EphemeralSecret {
            private_key,
            public_key: public_key_bytes,
        };

        assert_eq!(
            PublicKey(public_key_bytes),
            PublicKey::from(&ephemeral_secret)
        );
    }
}
