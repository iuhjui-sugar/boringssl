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
    use std::io::{self, Write};
    use std::mem;
    use std::process;
    use std::sync::{Mutex, MutexGuard, Once};

    static mut MUTEXES: *mut Vec<Mutex<()>> = 0 as *mut Vec<Mutex<()>>;
    static mut GUARDS: *mut Vec<Option<MutexGuard<'static, ()>>> =
        0 as *mut Vec<Option<MutexGuard<'static, ()>>>;

    unsafe extern "C" fn locking_function(
        mode: c_int,
        n: c_int,
        _file: *const c_char,
        _line: c_int,
    ) {
        let mutex = &(*MUTEXES)[n as usize];

        if mode & crate::CRYPTO_LOCK != 0 {
            (*GUARDS)[n as usize] = Some(mutex.lock().unwrap());
        } else {
            if let None = (*GUARDS)[n as usize].take() {
                let _ = writeln!(
                    io::stderr(),
                    "BUG: rust-openssl lock {} already unlocked, aborting",
                    n
                );
                process::abort();
            }
        }
    }

    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            fn set_id_callback() {
                unsafe extern "C" fn thread_id() -> c_ulong {
                    ::libc::pthread_self() as c_ulong
                }

                unsafe {
                    CRYPTO_set_id_callback(Some(thread_id));
                }
            }
        } else {
            fn set_id_callback() {}
        }
    }

    static INIT: Once = Once::new();

    INIT.call_once(|| unsafe {
        SSL_library_init();
        SSL_load_error_strings();
        // TODO(BWB) check this ben!!
        // OPENSSL_add_all_algorithms_noconf();
        OPENSSL_add_all_algorithms_conf();

        let num_locks = crate::CRYPTO_num_locks();
        let mut mutexes = Box::new(Vec::new());
        for _ in 0..num_locks {
            mutexes.push(Mutex::new(()));
        }
        MUTEXES = mem::transmute(mutexes);
        let guards: Box<Vec<Option<MutexGuard<()>>>> =
            Box::new((0..num_locks).map(|_| None).collect());
        GUARDS = mem::transmute(guards);

        CRYPTO_set_locking_callback(Some(locking_function));
        set_id_callback();
    })
}
