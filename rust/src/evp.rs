// #define PKCS5_DEFAULT_ITERATIONS 2048
// Not a potential ABI breakage
pub const PKCS12_DEFAULT_ITER: libc::c_int = 2048;

// Name alias
pub const EVP_PKEY_HMAC: libc::c_int = crate::NID_hmac;
