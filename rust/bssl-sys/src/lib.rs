#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// Set in build.rs
include!(env!("BINDGEN_RS_FILE"));

pub fn init() {
    unsafe {
        CRYPTO_library_init();
    }
}
