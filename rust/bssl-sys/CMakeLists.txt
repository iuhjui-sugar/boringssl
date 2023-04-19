# Additional interop for things like macros and inlined functions.
add_library(rust_wrapper STATIC rust_wrapper.c)
target_link_libraries(rust_wrapper crypto)


# Generate architecture-specific wrappers.
set(WRAPPER_TARGET ${CMAKE_CURRENT_BINARY_DIR}/src/wrapper_${RUST_BINDINGS}.rs)
set(COMMAND ${BINDGEN_EXECUTABLE} wrapper.h
            -o ${WRAPPER_TARGET}
            --no-derive-default
            --enable-function-attribute-detection
            --use-core
            --default-macro-constant-type=signed
            --rustified-enum=point_conversion_form_t
            # These regexes need to accept both / and \ to handle Windows file
            # path differences, due a bindgen issue. See
            # https://crbug.com/boringssl/595. Ideally, we would write [/\\],
            # but there are many layers of escaping here. First, CMake
            # interprets backslashes. Then CMake generates a Ninja or Make file.
            # That, in turn, launches passes inputs to the shell on POSIX, and
            # does something else on Windows.
            #
            # It is unlikely that every layer here has sufficiently well-defined
            # escaping and correctly handled the next layer's escaping. On top
            # of that, we'd likely need to detect Windows vs POSIX hosts and
            # change the input. Instead, just use [[:punct:]] which is more
            # permissive than necessary, but we only need to exclude unwanted
            # libc heaaders.
            #
            # If bindgen ever supports some file-based config (see
            # https://github.com/rust-lang/rust-bindgen/issues/2508), we can
            # switch to that.
            --allowlist-file=".*[[:punct:]]include[[:punct:]]openssl[[:punct:]].*\\.h"
            --allowlist-file=".*[[:punct:]]rust_wrapper\\.h"
            -- # these are LLVM arg passthroughs
            -I../../include
            # https://doc.rust-lang.org/nightly/rustc/platform-support.html
            --target=${RUST_BINDINGS})

# Ideally we'd use bindgen and ninja's depfile support but that didn't work when
# we tried it. There may be some mismatch in the syntax. Instead, explicitly
# depend on all our headers. This won't quite work right when adding a new
# header without re-running CMake. For that, we need depfiles.
file(GLOB headers ../../include/openssl/*.h)
add_custom_command(
  OUTPUT ${WRAPPER_TARGET}
  COMMAND ${COMMAND}
  DEPENDS wrapper.h ${headers}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
add_custom_target(bssl_sys ALL DEPENDS ${WRAPPER_TARGET})

# move files into build directory
configure_file("src/lib.rs" "src/lib.rs")

if(NOT BUILD_SHARED_LIBS)
  configure_file("build.rs" "build.rs" COPYONLY)
endif()

configure_file("Cargo.toml" "Cargo.toml" COPYONLY)
