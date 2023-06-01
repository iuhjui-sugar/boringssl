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

pub(crate) struct BigNum {
    ptr: *mut bssl_sys::BIGNUM,
}

impl BigNum {
    pub(crate) fn new() -> Self {
        // Safety: There are no preconditions for BN_new()
        Self::from_raw(unsafe { bssl_sys::BN_new() })
    }

    pub(crate) fn from_raw(ptr: *mut bssl_sys::BIGNUM) -> Self {
        assert!(!ptr.is_null());
        Self { ptr }
    }

    pub(crate) unsafe fn ptr(&self) -> *const bssl_sys::BIGNUM {
        self.ptr
    }

    pub(crate) unsafe fn ptr_mut(&mut self) -> *mut bssl_sys::BIGNUM {
        self.ptr
    }
}

impl From<&[u8]> for BigNum {
    fn from(value: &[u8]) -> Self {
        // Safety:
        // - `value` is a slice from safe Rust.
        // - The `ret` argument can be null to request allocating a new result.
        let ptr =
            unsafe { bssl_sys::BN_bin2bn(value.as_ptr(), value.len(), core::ptr::null_mut()) };
        assert!(!ptr.is_null());
        Self { ptr }
    }
}

impl Drop for BigNum {
    fn drop(&mut self) {
        // Safety: The `BigNum` struct ensures the validity of `self.ptr`
        unsafe { bssl_sys::BN_free(self.ptr) }
    }
}
