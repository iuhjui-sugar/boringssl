cmake_minimum_required(VERSION 2.8.11)
include_directories(../../include)

set(ASM_EXT S)
enable_language(ASM)
add_definitions(-pedantic)

# Compile to object files, we will link them with libssl
add_library(
    sike

    OBJECT

    src/isogeny.c
    src/fpx.c
    src/P503.c    
    src/sike.c
)

# Architecture specific settings
if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64" OR ${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm64")
    add_definitions(-lrt)
endif()

# Platform specific sources
if(OPENSSL_NO_ASM)
    target_sources(
        sike
        PRIVATE
        src/asm/fp_generic.c
    )
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    target_sources(
        sike

        PRIVATE

        src/asm/fp_x64_asm.${ASM_EXT}
    )
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64" OR ${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm64")
    target_sources(
        sike

        PRIVATE

        src/asm/fp_arm64_asm.${ASM_EXT}
    )
endif()

target_include_directories(sike PUBLIC
  include
)

add_executable(
    sike_test

    src/sike_test.cc

  $<TARGET_OBJECTS:sike>
  $<TARGET_OBJECTS:boringssl_gtest_main>
)

target_include_directories(sike_test PUBLIC
  include
)

target_link_libraries(sike_test test_support_lib boringssl_gtest crypto)
