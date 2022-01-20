# additional interop for things like macros and inlined functions
add_library(
  rust_wrapper
  STATIC
  rust_wrapper.c
)

# Map a boringssl ARCH variable to one of the supported Rust targets
# https://doc.rust-lang.org/nightly/rustc/platform-support.html
if(UNIX)
  if(ARCH STREQUAL "aarch64")
    set(TARGET "aarch64-unknown-linux-gnu")
  elseif(ARCH STREQUAL "x86_64")
    set(TARGET "x86_64-unknown-linux-gnu")
  else()
    message(FATAL_ERROR "No mapping from ${ARCH} on Unix to a known Rust triple.")
  endif()
elseif(WIN32)
  if(ARCH STREQUAL "x86_64")
    set(TARGET "x86_64-pc-windows-msvc")
  else()
    message(FATAL_ERROR "No mapping from ${ARCH} on Win32 to a known Rust triple.")
  endif()
else()
  message(FATAL_ERROR "No mapping from to a known Rust triple.")
endif()

# generate architecture specific wrappers
set(WRAPPER_TARGET ${CMAKE_BINARY_DIR}/rust/src/wrapper_${TARGET}.rs)
set(COMMAND ${BINDGEN_EXECUTABLE} "wrapper.h"
            -o ${WRAPPER_TARGET}
            --no-derive-default
            --enable-function-attribute-detection
            --use-core
            --size_t-is-usize
            --default-macro-constant-type="signed"
            --rustified-enum="point_conversion_form_t"
            # These are not BoringSSL symbols, they are from glibc
            # and are not relevant to the build besides throwing warnings
            # about their 'long double' (aka u128) not being FFI safe.
            # We block those functions so that the build doesn't
            # spam warnings.
            #
            # https://github.com/rust-lang/rust-bindgen/issues/1549 describes the current problem
            # and other folks' solutions.
            #
            # We will explore migrating to https://github.com/rust-lang/rust-bindgen/pull/2122
            # when it lands
            --blocklist-function="strtold"
            --blocklist-function="qecvt"
            --blocklist-function="qecvt_r"
            --blocklist-function="qgcvt"
            --blocklist-function="qfcvt"
            --blocklist-function="qfcvt_r"
            -- # these are LLVM arg passthroughs
            -I../include
            --target=${TARGET})

set(INCLUDES "include!(\"wrapper_${TARGET}.rs\");\n")

add_custom_target(
  bindgen_rust_${TARGET}
  ALL
  ${COMMAND}
  BYPRODUCTS ${WRAPPER_TARGET}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# move files into build directory
configure_file("src/lib.rs" "src/lib.rs")

if(NOT BUILD_SHARED_LIBS)
  configure_file("build.rs" "build.rs" COPYONLY)
endif()

configure_file("Cargo.toml" "Cargo.toml" COPYONLY)
