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

//! `EcKey` and `EcGroup` classes for implementing elliptic curve cryptography. This module is
//! intended for internal use within this crate only, to create higher-level abstractions suitable
//! to be exposed externally.

use core::panic;

use crate::{bn::BigNum, ForeignType};

#[derive(Debug)]
pub(crate) struct EcKey {
    ptr: *mut bssl_sys::EC_KEY,
}

// Safety: Implementation ensures `from_ptr(x).as_ptr() == x`
unsafe impl ForeignType for EcKey {
    type CType = bssl_sys::EC_KEY;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self { ptr }
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.ptr
    }
}

// Safety:
// - `EC_KEY`'s documentation says "A given object may be used concurrently on multiple threads by
//   non-mutating functions, provided no other thread is concurrently calling a mutating function.",
//   which matches Rust's aliasing rules.
// - `ptr(&self)` and `ptr_mut(&mut self)` ensures that only a mutable reference can get a mutable
//   `EC_KEY` pointer outside of this module.
unsafe impl Send for EcKey {}

impl Clone for EcKey {
    fn clone(&self) -> Self {
        // Safety:
        // - EcKey makes sure self.ptr is a valid pointer.
        let ptr = unsafe { bssl_sys::EC_KEY_dup(self.ptr) };
        Self { ptr }
    }
}

/// Error type returned when conversion to or from an `EcKey` failed.
pub(crate) struct ConversionFailed;

impl EcKey {
    pub fn new_by_curve_name(nid: i32) -> Self {
        let eckey = unsafe { bssl_sys::EC_KEY_new_by_curve_name(nid) };
        assert!(!eckey.is_null());
        // Safety: `eckey` is allocated and null-checked
        unsafe { Self::from_ptr(eckey) }
    }

    /// Try to create a public-key version of `EcKey` from the given `value`. Returns error if the
    /// slice is not a valid representation of a public key for the given curve.
    ///
    /// `curve_nid` should be a value defined in `bssl_sys::NID_*`.
    #[allow(clippy::panic)]
    pub(crate) fn try_new_public_key_from_bytes(
        curve_nid: i32,
        value: &[u8],
    ) -> Result<Self, ConversionFailed> {
        let eckey = Self::new_by_curve_name(curve_nid);

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
            0 => Err(ConversionFailed),
            1 => Ok(eckey),
            _ => panic!("Unexpected return value {result} from EC_POINT_oct2point"),
        }
    }

    pub(crate) fn to_affine_coordinates(&self) -> (BigNum, BigNum) {
        let ecpoint = unsafe { bssl_sys::EC_KEY_get0_public_key(self.ptr) };
        let bn_x = BigNum::new();
        let bn_y = BigNum::new();

        // Safety:
        // - `EcKey` and `BigNum` structs ensures validity of their pointers.
        let result = unsafe {
            bssl_sys::EC_POINT_get_affine_coordinates(
                bssl_sys::EC_KEY_get0_group(self.ptr),
                ecpoint,
                bn_x.as_ptr(),
                bn_y.as_ptr(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(
            result, 1,
            "bssl_sys::EC_POINT_get_affine_coordinates failed"
        );
        (bn_x, bn_y)
    }

    pub(crate) fn generate(curve_nid: i32) -> Self {
        let mut eckey = EcKey::new_by_curve_name(curve_nid);
        // Safety: `EcKey` ensures eckey.ptr is valid.
        let result = unsafe { bssl_sys::EC_KEY_generate_key(eckey.as_ptr()) };
        assert_eq!(result, 1, "bssl_sys::EC_KEY_generate_key failed");
        eckey
    }

    pub(crate) fn try_new_public_key_from_affine_coordinates(
        curve_nid: i32,
        x: &[u8],
        y: &[u8],
    ) -> Result<Self, ()> {
        let bn_x = BigNum::from(x);
        let bn_y = BigNum::from(y);

        let mut eckey = EcKey::new_by_curve_name(curve_nid);
        // Safety:
        // - Wrapper classes `EcKey` and `BigNum` ensures validity of the pointers
        let result = unsafe {
            bssl_sys::EC_KEY_set_public_key_affine_coordinates(
                eckey.as_ptr(),
                bn_x.as_ptr(),
                bn_y.as_ptr(),
            )
        };
        if result == 1 {
            Ok(eckey)
        } else {
            Err(())
        }
    }

    /// Tries to convert the given bytes into a private key contained within `EcKey`.
    ///
    /// `private_key_bytes` must be padded to the size of `curve_nid`'s group order, otherwise the
    /// conversion will fail.
    pub(crate) fn try_from_raw_bytes(
        curve_nid: i32,
        private_key_bytes: &[u8],
    ) -> Result<Self, ConversionFailed> {
        let mut eckey = EcKey::new_by_curve_name(curve_nid);
        // Safety:
        // - `EcKey` ensures `eckey.ptr` is valid.
        // - private_key_bytes is a slice from safe-rust.
        let result = unsafe {
            bssl_sys::EC_KEY_oct2priv(
                eckey.as_ptr(),
                private_key_bytes.as_ptr(),
                private_key_bytes.len(),
            )
        };
        if result != 1 {
            return Err(ConversionFailed);
        }

        Ok(eckey)
    }

    pub(crate) fn public_key_eq(&self, other: &Self) -> bool {
        let result = unsafe {
            bssl_sys::EC_POINT_cmp(
                bssl_sys::EC_KEY_get0_group(self.ptr),
                bssl_sys::EC_KEY_get0_public_key(self.ptr),
                bssl_sys::EC_KEY_get0_public_key(other.ptr),
                core::ptr::null_mut(),
            )
        };
        assert_ne!(result, -1, "bssl_sys::EC_POINT_cmp failed");
        result == 0
    }

    pub(crate) fn to_vec(&self) -> Vec<u8> {
        // Safety: `self.ptr` is owned by `self`
        let ecgroup = unsafe { bssl_sys::EC_KEY_get0_group(self.ptr) };
        let ecpoint = unsafe { bssl_sys::EC_KEY_get0_public_key(self.ptr) };
        let conv_form = unsafe { bssl_sys::EC_KEY_get_conv_form(self.ptr) };
        // Safety:
        // - When passing null to EC_POINT_point2oct's `buf` argument, it returns the size of the
        //   resulting buffer.
        let output_size = unsafe {
            bssl_sys::EC_POINT_point2oct(
                ecgroup,
                ecpoint,
                conv_form,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
            )
        };
        assert_ne!(output_size, 0, "bssl_sys::EC_KEY_key2buf failed");
        let mut result_vec = Vec::<u8>::with_capacity(output_size);
        let buf_len = unsafe {
            bssl_sys::EC_POINT_point2oct(
                ecgroup,
                ecpoint,
                conv_form,
                result_vec.as_mut_ptr(),
                output_size,
                core::ptr::null_mut(),
            )
        };
        assert_ne!(buf_len, 0, "bssl_sys::EC_KEY_key2buf failed");
        // Safety: The length is what EC_POINT_point2oct just told us it filled into the buffer.
        unsafe { result_vec.set_len(buf_len) }
        result_vec
    }
}

impl Drop for EcKey {
    fn drop(&mut self) {
        // Safety: `self.ptr` is owned by this struct
        unsafe { bssl_sys::EC_KEY_free(self.ptr) }
    }
}
