use libc::{c_uint, c_int, c_ulonglong, c_char};

#[cfg(target_pointer_width = "64")]
pub type BN_ULONG = c_ulonglong;
#[cfg(target_pointer_width = "32")]
pub type BN_ULONG = c_uint;

pub use crate::BIGNUM;
