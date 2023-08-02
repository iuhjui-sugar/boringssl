/* Copyright (c) 2021, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

use std::env;
use std::path::Path;
use std::path::PathBuf;

use bindgen::MacroTypeVariation;

pub fn run_bindgen(output: &Path, target: &str, project_dir: &Path) {
    let depfile = {
        let extension = match output.extension() {
            Some(e) => {
                let mut e = e.to_os_string();
                e.push(".d");
                e
            },
            None => "d".into(),
        };
        output.with_extension(extension)
    };

    let project_dir = project_dir.to_str()
        .expect("project_dir contains invalid UTF-8 characters");
    let output = output.to_str()
        .expect("output contains invalid UTF-8 characters");
    let depfile = depfile.to_str()
        .unwrap();

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .depfile(output, depfile)
        .derive_default(false)
        .enable_function_attribute_detection()
        .use_core()
        .default_macro_constant_type(MacroTypeVariation::Signed)
        .rustified_enum("point_conversion_form_t")
        // These regexes need to accept both / and \ to handle Windows file
        // path differences, due a bindgen issue. See
        // https://crbug.com/boringssl/595. Ideally, we would write [/\\], but
        // there are many layers of escaping here. First, CMake interprets
        // backslashes. Then CMake generates a Ninja or Make file. That, in
        // turn, uses the shell on POSIX, and does something else on Windows.
        //
        // It is unlikely that every layer here has sufficiently well-defined
        // escaping and correctly handled the next layer's escaping. On top of
        // that, we'd likely need to detect Windows vs POSIX hosts and change
        // the input. Instead, just use [[:punct:]] which is more permissive
        // than necessary, but we only need to exclude unwanted libc headers.
        //
        // If bindgen ever supports some file-based config (see
        // https://github.com/rust-lang/rust-bindgen/issues/2508), we can
        // switch to that.
        .allowlist_file(r".*[[:punct:]]include[[:punct:]]openssl[[:punct:]].*\.h")
        .allowlist_file(r".*[[:punct:]]rust_wrapper\.h")
        .clang_arg(format!("-I{}/include", project_dir))
        // https://doc.rust-lang.org/nightly/rustc/platform-support.html
        .clang_arg(format!("--target={}", target))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(output)
        .expect("Unable to write bindings");
}

fn path_from_env_or_crate_relative(env_name: &str, rel_fallback: &str) -> PathBuf {
    println!("cargo:rerun-if-env-changed={env_name}");
    if let Some(path) = env::var_os(env_name) {
        return PathBuf::from(path);
    }

    let crate_dir = env::var_os("CARGO_MANIFEST_DIR")
        .unwrap();
    return Path::new(&crate_dir).join(rel_fallback);
}

fn main() {
    let project_dir = path_from_env_or_crate_relative("PROJECT_SOURCE_DIR", "../..");
    let bssl_build_dir = path_from_env_or_crate_relative("PROJECT_BINARY_DIR", "../../build");
    let bssl_sys_build_dir = bssl_build_dir.join("rust/bssl-sys");
    let target = env::var("TARGET").unwrap();

    // Find the bindgen generated target platform bindings file and set BINDGEN_RS_FILE
    let bindgen_file = bssl_sys_build_dir.join(format!("wrapper_{}.rs", target));
    run_bindgen(&bindgen_file, &target, &project_dir);
    println!("cargo:rustc-env=BINDGEN_RS_FILE={}", bindgen_file.display());

    // Statically link libraries.
    println!(
        "cargo:rustc-link-search=native={}",
        bssl_build_dir.join("crypto").display()
    );
    println!("cargo:rustc-link-lib=static=crypto");

    println!(
        "cargo:rustc-link-search=native={}",
        bssl_build_dir.join("ssl").display()
    );
    println!("cargo:rustc-link-lib=static=ssl");

    println!(
        "cargo:rustc-link-search=native={}",
        bssl_sys_build_dir.display()
    );
    println!("cargo:rustc-link-lib=static=rust_wrapper");
}
