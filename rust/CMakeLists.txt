# additional interop for things like macros and inlined functions
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include)
# generate architecture specific wrappers
set(WRAPPER_TARGET ${CMAKE_BINARY_DIR}/rust/src/wrapper_${RUST_BINDINGS}.rs)
# XXX: remove hard-coding of path
set(COMMAND /tmp/rust-bindgen/target/release/bindgen "wrapper.h"
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
            --blocklist-function="_OSSwap.*"
            --blocklist-function="OSReadSwap.*"
            --blocklist-function="OSWriteSwap.*"
            --experimental
            --wrap-static-fns
            --wrap-static-fns-path="${CMAKE_BINARY_DIR}/rust/wrapper.c"
            -- # these are LLVM arg passthroughs
            -I../include
            # https://doc.rust-lang.org/nightly/rustc/platform-support.html
            --target=${RUST_BINDINGS})

set(INCLUDES "include!(\"wrapper_${RUST_BINDINGS}.rs\");\n")

add_custom_target(
  bindgen_rust_${RUST_BINDINGS}
  ALL
  ${COMMAND}
  BYPRODUCTS ${WRAPPER_TARGET} ${CMAKE_BINARY_DIR}/rust/wrapper.c
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_library(
  rust_wrapper
  STATIC
  ${CMAKE_BINARY_DIR}/rust/wrapper.c
)
target_compile_options(rust_wrapper PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/wrapper.h)

# move files into build directory
configure_file("src/lib.rs" "src/lib.rs")

if(NOT BUILD_SHARED_LIBS)
  configure_file("build.rs" "build.rs" COPYONLY)
endif()

configure_file("Cargo.toml" "Cargo.toml" COPYONLY)

install(FILES ${WRAPPER_TARGET} DESTINATION rust/)
install(TARGETS rust_wrapper DESTINATION rust/)
