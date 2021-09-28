// Not a potential ABI breakage, just a sane default.
pub const PKCS12_DEFAULT_ITER: libc::c_int = 2048;

// Name alias
pub const EVP_PKEY_HMAC: libc::c_int = crate::NID_hmac;
