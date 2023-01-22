#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// populated by cmake
${INCLUDES}

pub fn ERR_GET_LIB(packed_error: u32) -> i32 {
    unsafe { ERR_get_lib(packed_error) }
}

pub fn ERR_GET_REASON(packed_error: u32) -> i32 {
    unsafe { ERR_get_reason(packed_error) }
}

pub fn ERR_GET_FUNC(packed_error: u32) -> i32 {
    unsafe { ERR_get_func(packed_error) }
}

pub fn init() {
    unsafe { CRYPTO_library_init(); }
}
