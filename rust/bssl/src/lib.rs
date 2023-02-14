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

#![deny(
    missing_docs,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used
)]

//! Rust boringssl binding

extern crate core;
use core::ops::Not;

/// boringssl implemented hmac operations
pub mod hmac;

/// boringssl implemented hash functions
pub mod digest;

/// Used for handling result types from C APIs
trait PanicResultHandler {
    /// panics if a C api returns an invalid result
    /// Used for APIs which return error codes for allocation failures
    fn panic_if_error(&self);
}

impl PanicResultHandler for i32 {
    /// boringssl APIs return 1 on success or 0 on allocation failure
    #[allow(clippy::expect_used)]
    fn panic_if_error(&self) {
        self.gt(&0).then_some(()).expect("allocation failed!")
    }
}

impl<T> PanicResultHandler for *mut T {
    /// boringssl APIs return NULL on allocation failure for APIs that return a CTX
    #[allow(clippy::expect_used)]
    fn panic_if_error(&self) {
        self.is_null()
            .not()
            .then_some(())
            .expect("allocation failed!")
    }
}
