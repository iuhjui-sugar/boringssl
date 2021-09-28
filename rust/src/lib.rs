#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::os::raw::*;

mod evp;
mod crypto;
mod obj_mac;
mod bn;

pub use evp::*;
pub use crypto::*;
pub use obj_mac::*;
pub use bn::*;

pub const DTLS1_COOKIE_LENGTH: c_uint = 256;

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
    use std::ptr;                                                                                          
    use std::sync::Once;                                                                                   
                                                                                                           
    // explicitly initialize to work around https://github.com/openssl/openssl/issues/3505                 
    static INIT: Once = Once::new();                                                                       
                                                                                                           
    #[cfg(not(ossl111b))]                                                                                  
    let init_options = OPENSSL_INIT_LOAD_SSL_STRINGS;                                                      
    #[cfg(ossl111b)]                                                                                       
    let init_options = OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_NO_ATEXIT;                             
                                                                                                           
    INIT.call_once(|| unsafe {                                                                             
        OPENSSL_init_ssl(init_options, ptr::null_mut());                                                   
    })                                                                                                     
}
