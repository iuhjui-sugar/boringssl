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

use crate::ForeignTypeRef;

/// The BoringSSL implemented SHA-256 digest algorithm.
#[derive(Clone)]
pub struct Sha256 {}

/// The BoringSSL implemented SHA-512 digest algorithm.
#[derive(Clone)]
pub struct Sha512 {}

/// A reference to an [`Md`], which abstracts the details of a specific hash function allowing code
/// to deal with the concept of a "hash function" without needing to know exactly which hash function
/// it is.
#[non_exhaustive]
pub struct MdRef;

unsafe impl ForeignTypeRef for MdRef {
    type CType = bssl_sys::EVP_MD;
}

/// Used internally to get a BoringSSL internal MD
pub trait Md {
    /// The output size of the hash operation.
    const OUTPUT_SIZE: usize;

    /// Gets a reference to a message digest algorithm to be used by the hkdf implementation.
    fn get_md() -> &'static MdRef;
}

impl Md for Sha256 {
    const OUTPUT_SIZE: usize = bssl_sys::SHA256_DIGEST_LENGTH as usize;

    fn get_md() -> &'static MdRef {
        // Safety:
        // - this always returns a valid pointer to an EVP_MD
        unsafe { MdRef::from_ptr(bssl_sys::EVP_sha256() as *mut _) }
    }
}

impl Md for Sha512 {
    const OUTPUT_SIZE: usize = bssl_sys::SHA512_DIGEST_LENGTH as usize;

    fn get_md() -> &'static MdRef {
        // Safety:
        // - this always returns a valid pointer to an EVP_MD
        unsafe { MdRef::from_ptr(bssl_sys::EVP_sha512() as *mut _) }
    }
}

///
pub struct Digest<const DIGEST_SIZE: usize>(bssl_sys::EVP_MD_CTX);

impl<const DIGEST_SIZE: usize> Digest<DIGEST_SIZE> {
    ///
    pub fn new(md: &MdRef) -> Self {
        let mut md_ctx_uninit = core::mem::MaybeUninit::<bssl_sys::EVP_MD_CTX>::uninit();
        // Safety:
        // - `EVP_DigestInit` initializes `md_ctx_uninit`
        // - `MdRef` ensures the validity of `md.as_ptr`
        let result = unsafe {
            bssl_sys::EVP_DigestInit(md_ctx_uninit.as_mut_ptr(), md.as_ptr())
        };
        assert_eq!(result, 1, "bssl_sys::EVP_DigestInit failed");
        // Safety:
        // - md_ctx_uninit initialized with EVP_DigestInit, and the function returned 1 (success)
        let md_ctx = unsafe { md_ctx_uninit.assume_init() };
        Self(md_ctx)
    }

    ///
    pub fn update(&mut self, data: &[u8]) {
        // Safety:
        // - `data` is a slice from safe Rust.
        let result = unsafe {
            bssl_sys::EVP_DigestUpdate(
                &mut self.0,
                data.as_ptr() as *const _,
                data.len(),
            )
        };
        assert_eq!(result, 1, "bssl_sys::EVP_DigestUpdate failed");
    }

    ///
    #[allow(clippy::expect_used)]
    pub fn finalize(mut self) -> [u8; DIGEST_SIZE] {
        let mut digest_uninit =
            core::mem::MaybeUninit::<[u8; bssl_sys::EVP_MAX_MD_SIZE as usize]>::uninit();
        let mut len_uninit = core::mem::MaybeUninit::<u32>::uninit();
        // Safety:
        // - `digest_uninit` is allocated to `EVP_MAX_MD_SIZE` bytes long, as required by
        //   EVP_DigestFinal_ex
        // - `self.0` is owned by `self`, and is going to be cleaned up on drop.
        let result = unsafe {
            bssl_sys::EVP_DigestFinal_ex(
                &mut self.0,
                digest_uninit.as_mut_ptr() as *mut _,
                len_uninit.as_mut_ptr(),
            )
        };
        assert_eq!(result, 1, "bssl_sys::EVP_DigestFinal_ex failed");
        // Safety:
        // - `len_uninit` is initialized by `EVP_DigestFinal_ex`, and we checked the result above
        let len = unsafe { len_uninit.assume_init() };
        assert_eq!(
            DIGEST_SIZE, len as usize,
            "bssl_sys::EVP_DigestFinal_ex failed"
        );
        // Safety: Result of DigestFinal_ex was checked above
        let digest = unsafe { digest_uninit.assume_init() };
        digest.get(..DIGEST_SIZE)
            .and_then(|digest| digest.try_into().ok())
            .expect("The length of `digest` was checked above")
    }
}

impl<const DIGEST_SIZE: usize> Drop for Digest<DIGEST_SIZE> {
    fn drop(&mut self) {
        // Safety: `self.0` is owned by `self`, and is invalidated after `drop`.
        unsafe {
            bssl_sys::EVP_MD_CTX_cleanup(&mut self.0);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sha256_c_type() {
        unsafe {
            assert_eq!(
                MdRef::from_ptr(bssl_sys::EVP_sha256() as *mut _).as_ptr(),
                bssl_sys::EVP_sha256() as *mut _
            )
        }
    }

    #[test]
    fn test_sha512_c_type() {
        unsafe {
            assert_eq!(
                MdRef::from_ptr(bssl_sys::EVP_sha512() as *mut _).as_ptr(),
                bssl_sys::EVP_sha512() as *mut _
            )
        }
    }
}
