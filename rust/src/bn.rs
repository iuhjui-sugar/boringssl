use libc::{c_uint, c_ulonglong};

#[cfg(target_pointer_width = "64")]
pub type BN_ULONG = c_ulonglong;
#[cfg(target_pointer_width = "32")]
pub type BN_ULONG = c_uint;

pub use crate::BIGNUM;
