extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo to tell rustc to link the system bzip2
    // shared library.
    println!("cargo:rustc-link-search=native=../crypto");
    println!("cargo:rustc-link-search=native=../ssl");
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");
    //println!("cargo:rustc-link-search=../crypto");
    //println!("cargo:rustc-link-lib=libcrypto");
}
