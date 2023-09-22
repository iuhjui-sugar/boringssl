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

//! `Pkey` and `PkeyCtx` classes for holding asymmetric keys. This module is intended for internal
//! use within this crate only, to create higher-level abstractions suitable to be exposed
//! externally.

use crate::{ec::EcKey, CSliceMut, ForeignType as _};
use alloc::borrow::ToOwned;
use alloc::string::String;
use foreign_types::{foreign_type, ForeignType};

foreign_type! {
    type CType = bssl_sys::EVP_PKEY;
    fn drop = bssl_sys::EVP_PKEY_free;

    /// A foreign type representation of `EVP_PKEY`.
    pub struct Pkey;
    /// A borrowed `EVP_PKEY`.
    pub struct PkeyRef;
}

impl From<&EcKey> for Pkey {
    fn from(eckey: &EcKey) -> Self {
        // Safety: EVP_PKEY_new does not have any preconditions
        let pkey = unsafe { bssl_sys::EVP_PKEY_new() };
        assert!(!pkey.is_null());
        // Safety:
        // - pkey is just allocated and is null-checked
        // - EcKey ensures eckey.ptr is valid during its lifetime
        // - EVP_PKEY_set1_EC_KEY doesn't take ownership
        let result = unsafe { bssl_sys::EVP_PKEY_set1_EC_KEY(pkey, eckey.as_ptr()) };
        assert_eq!(result, 1, "bssl_sys::EVP_PKEY_set1_EC_KEY failed");
        // SAFETY: `pkey` has been checked as non-null.
        unsafe { Self::from_ptr(pkey) }
    }
}

foreign_type! {
    type CType = bssl_sys::EVP_PKEY_CTX;
    fn drop = bssl_sys::EVP_PKEY_CTX_free;

    /// A foreign type representation of `EVP_PKEY_CTX`.
    pub struct PkeyCtx;
    /// A borrowed `EVP_PKEY_CTX`.
    pub struct PkeyCtxRef;
}

impl PkeyCtx {
    pub fn new(pkey: &Pkey) -> Self {
        // Safety:
        // - `Pkey` ensures `pkey.ptr` is valid, and EVP_PKEY_CTX_new does not take ownership.
        let pkeyctx = unsafe { bssl_sys::EVP_PKEY_CTX_new(pkey.as_ptr(), core::ptr::null_mut()) };
        assert!(!pkeyctx.is_null());
        // SAFETY: `pkeyctx` has been checked as non-null.
        unsafe { Self::from_ptr(pkeyctx) }
    }

    #[allow(clippy::panic)]
    pub(crate) fn diffie_hellman(
        self,
        other_public_key: &Pkey,
        mut output: CSliceMut,
    ) -> Result<(), String> {
        let result = unsafe { bssl_sys::EVP_PKEY_derive_init(self.as_ptr()) };
        assert_eq!(result, 1, "bssl_sys::EVP_PKEY_derive_init failed");

        let result =
            unsafe { bssl_sys::EVP_PKEY_derive_set_peer(self.as_ptr(), other_public_key.as_ptr()) };
        assert_eq!(result, 1, "bssl_sys::EVP_PKEY_derive_set_peer failed");

        let result = unsafe {
            bssl_sys::EVP_PKEY_derive(self.as_ptr(), output.as_mut_ptr(), &mut output.len())
        };
        match result {
            0 => Err("bssl_sys::EVP_PKEY_derive failed".to_owned()),
            1 => Ok(()),
            _ => panic!("Unexpected result {result:?} from bssl_sys::EVP_PKEY_derive"),
        }
    }
}
