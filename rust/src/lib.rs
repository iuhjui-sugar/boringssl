#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::os::raw::*;

mod bn;
mod nid;

pub use bn::*;
pub use nid::*;

// Non-ABI breaking constants
pub const DTLS1_COOKIE_LENGTH: c_uint = 256;
pub const PKCS12_DEFAULT_ITER: libc::c_int = 2048;

// populated by cmake
${INCLUDES}

pub fn ERR_GET_LIB(packed_error: u32) -> i32 {
    ((packed_error >> 24) & 0xff) as i32
}

pub fn ERR_GET_REASON(packed_error: u32) -> i32 {
    (packed_error & 0xfff) as i32
}

pub fn ERR_GET_FUNC(packed_error: u32) -> i32 {
    0
}

pub fn init() {
    unsafe { CRYPTO_library_init(); }
}
