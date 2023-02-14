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

use foreign_types::{ForeignTypeRef, Opaque};

/// Trait covering functionality of cryptographic hash functions with fixed output size.
pub trait Digest<const N: usize> {
    /// Create new hasher instance.
    fn new() -> Self;

    /// Process data, updating the internal state.
    fn update(&mut self, input: &[u8]);

    /// Retrieve result and consume hasher instance.
    fn finalize(self) -> [u8; N];

    /// Compute one shot hash of `data`.
    fn digest(input: &[u8]) -> [u8; N];
}

/// openssl sha256 digest algorithm
#[derive(Clone)]
pub struct Sha256 {}

/// openssl sha512 digest algorithm
#[derive(Clone)]
pub struct Sha512 {}

impl Digest<32> for Sha256 {
    fn new() -> Self {
        todo!()
    }

    fn update(&mut self, _input: &[u8]) {
        todo!()
    }

    fn finalize(self) -> [u8; 32] {
        todo!()
    }

    fn digest(_input: &[u8]) -> [u8; 32] {
        todo!()
    }
}

impl Digest<64> for Sha512 {
    fn new() -> Self {
        todo!()
    }

    fn update(&mut self, _input: &[u8]) {
        todo!()
    }

    fn finalize(self) -> [u8; 64] {
        todo!()
    }

    fn digest(_input: &[u8]) -> [u8; 64] {
        todo!()
    }
}

/// A reference to an [`Md`], which abstracts the details of a specific hash function allowing code
/// to deal with the concept of a "hash function" without needing to know exactly which hash function
/// it is
pub(crate) struct MdRef(Opaque);

unsafe impl ForeignTypeRef for MdRef {
    type CType = bssl_sys::EVP_MD;
}

/// used internally to get a bssl internal md
pub(crate) trait Md {
    /// gets a reference to a message digest algorithm to be used by the hkdf implementation
    fn get_md() -> &'static MdRef;
}

impl Md for Sha256 {
    fn get_md() -> &'static MdRef {
        // Safety:
        // - this always returns a valid pointer to an EVP_MD
        unsafe { MdRef::from_ptr(bssl_sys::EVP_sha256() as *mut _) }
    }
}

impl Md for Sha512 {
    fn get_md() -> &'static MdRef {
        // Safety:
        // - this always returns a valid pointer to an EVP_MD
        unsafe { MdRef::from_ptr(bssl_sys::EVP_sha512() as *mut _) }
    }
}
