use foreign_types::{ForeignTypeRef, Opaque};

/// Trait covering functionality of cryptographic hash functions with fixed output size.
pub trait Digest<const N: usize> {
    /// gets a reference to a message digest algorithm to be used by the hkdf implementation
    fn get_md() -> &'static MdRef;

    /// Create new hasher instance.
    fn new() -> Self;

    /// Process data, updating the internal state.
    fn update(&mut self, input: &[u8]);

    /// Retrieve result and consume hasher instance.
    fn finalize(self) -> [u8; N];

    /// Compute one shot hash of `data`.
    fn digest(input: &[u8]) -> [u8; N];
}

/// openssl sha256 digest algorithm
#[derive(Clone)]
pub struct Sha256 {}

/// openssl sha512 digest algorithm
#[derive(Clone)]
pub struct Sha512 {}

/// A reference to an [`Md`].
pub struct MdRef(Opaque);

unsafe impl ForeignTypeRef for MdRef {
    type CType = bssl_sys::EVP_MD;
}

impl Digest<32> for Sha256 {
    fn get_md() -> &'static MdRef {
        //Safety:
        // - TODO:
        unsafe { MdRef::from_ptr(bssl_sys::EVP_sha256() as *mut _) }
    }

    fn new() -> Self {
        todo!()
    }

    fn update(&mut self, _input: &[u8]) {
        todo!()
    }

    fn finalize(self) -> [u8; 32] {
        todo!()
    }

    fn digest(_input: &[u8]) -> [u8; 32] {
        todo!()
    }
}

impl Digest<64> for Sha512 {
    fn get_md() -> &'static MdRef {
        //Safety:
        // - TODO:
        unsafe { MdRef::from_ptr(bssl_sys::EVP_sha512() as *mut _) }
    }

    fn new() -> Self {
        todo!()
    }

    fn update(&mut self, _input: &[u8]) {
        todo!()
    }

    fn finalize(self) -> [u8; 64] {
        todo!()
    }

    fn digest(_input: &[u8]) -> [u8; 64] {
        todo!()
    }
}
