# generate architecture specific wrappers
foreach(TARGET
    #    aarch64-unknown-linux-gnu
    #    i686-pc-windows-gnu
    x86_64-unknown-linux-gnu
  )

  set(WRAPPER_TARGET ${CMAKE_BINARY_DIR}/rust/src/wrapper_${TARGET}.rs)
  set(COMMAND ${BINDGEN_EXECUTABLE} "wrapper.h"
              -o ${WRAPPER_TARGET}
              --no-derive-default
              #              --no-derive-debug
              #--no-derive-copy
              --enable-function-attribute-detection
              --use-core
              --size_t-is-usize
              --rust-target nightly
              --default-macro-constant-type="signed"
              --rustified-enum="point_conversion_form_t"
              -- # these are LLVM arg passthroughs
              -I../include
              --target=${TARGET})

  add_custom_target(
    bindgen_rust_${TARGET}
    ALL
    ${COMMAND}
    BYPRODUCTS ${WRAPPER_TARGET}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  )

string(REPLACE "-" ";" TARGET_LIST ${TARGET})
list(GET TARGET_LIST 0 ARCH)
list(GET TARGET_LIST 1 VENDOR)

set(INCLUDES "${INCLUDES}\
#[cfg(all(target_arch = \"${ARCH}\",target_vendor = \"${VENDOR}\"))]\n\
include!(\"wrapper_${TARGET}.rs\");\n")
endforeach()

# move files into build directory
configure_file("src/lib.rs" "src/lib.rs")

configure_file("build.rs" "build.rs" COPYONLY)

# type size
configure_file("src/bn.rs" "src/bn.rs" COPYONLY)

# C externs are define aliases only
# #define CRYPTO_malloc OPENSSL_malloc
configure_file("src/crypto.rs" "src/crypto.rs" COPYONLY)

# constants
configure_file("src/evp.rs" "src/evp.rs" COPYONLY)

# constants
configure_file("src/obj_mac.rs" "src/obj_mac.rs" COPYONLY)
configure_file("Cargo.toml" "Cargo.toml" COPYONLY)
