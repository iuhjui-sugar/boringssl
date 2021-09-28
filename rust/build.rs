fn main() {
    // Statically link libraries.
    println!("cargo:rustc-link-search=native=../crypto");
    println!("cargo:rustc-link-search=native=../ssl");
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");
}
