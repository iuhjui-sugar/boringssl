// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

//! Low-level crate providing FFI access to BoringSSL functionality.
//!
//! Almost all the code in this crate is produced by bindgen running
//! over the BoringSSL headers. The only manually generated code is
//! - an `init()` function
//! - Rust equivalents to function-like preprocessor macros defined in the
//!   BoringSSL headers (as bindgen doesn't cope with them).
#![no_std]

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused_imports)]

use libc::*;

// populated by cmake
${INCLUDES}

// The following Rust functions are equivalent to the preprocessor macros of the same
// name in the BoringSSL include files.  Each invokes the corresponding ..._MACRO()
// C function via FFI, and that C function is implemented in terms of the preprocessor
// macro.
//
// (It would be simpler to just re-implement each of the preprocessor macros in Rust,
// but that would be vulnerable to getting out of sync -- if the .h file changed, there
// would be no trigger to make the corresponding change here.)

pub fn ERR_GET_LIB(packed_error: u32) -> i32 {
    // Implementation:  ((packed_error >> 24) & 0xff) as i32
    unsafe { ERR_GET_LIB_MACRO(packed_error) }
}

pub fn ERR_GET_REASON(packed_error: u32) -> i32 {
    // Implementation:  (packed_error & 0xfff) as i32
    unsafe { ERR_GET_REASON_MACRO(packed_error) }
}

pub fn ERR_GET_FUNC(packed_error: u32) -> i32 {
    // Implementation:  0i32
    // Note that the (pre-3.0) OpenSSL implementation of this macro produces a
    // different, non-zero, result.
    // (OpenSSL 3.0 removes ERR_GET_FUNC altogether.)
    unsafe { ERR_GET_FUNC_MACRO(packed_error) }
}

pub fn init() {
    unsafe { CRYPTO_library_init(); }
}
