# Additional interop for things like macros and inlined functions.
add_library(rust_wrapper STATIC rust_wrapper.c)
target_link_libraries(rust_wrapper crypto)

# Generate architecture-specific wrappers. bindgen must be called from
# ${CMAKE_BINARY_DIR}, with the output path as a relative path. bindgen writes
# the depfile using the same syntax as the command-line argument, and ninja
# requires a path relative to the top-level build directory.
set(wrapper wrapper_${RUST_BINDINGS}.rs)

add_custom_command(
  OUTPUT ${wrapper}
  COMMAND ${CMAKE_COMMAND} -E
    env
      "PROJECT_BINARY_DIR=${PROJECT_BINARY_DIR}"
      "PROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}"
    cargo check
      --features _bindgen_only
      --target-dir "${CMAKE_CURRENT_BINARY_DIR}/target"
  DEPENDS wrapper.h
  DEPFILE ${CMAKE_CURRENT_BINARY_DIR}/${wrapper}.d
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
add_custom_target(bssl_sys ALL DEPENDS ${wrapper})
