use libc::{c_void, c_int, c_char};

extern "C" {
    pub fn CRYPTO_malloc(num: c_int, file: *const c_char, line: c_int) -> *mut c_void;
    pub fn CRYPTO_free(buf: *mut c_void);
}
