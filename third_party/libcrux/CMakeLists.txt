cmake_minimum_required(VERSION 3.12)

project(BoringSSLLibcrux
    LANGUAGES C CXX
)

file(GLOB_RECURSE sources src/*.c)
add_library(libcrux ${sources})
target_include_directories(libcrux PUBLIC
    include
    include/internal
    karamel/include
    karamel/krmllib/dist/minimal
)

# A quick test
include(FetchContent)
FetchContent_Declare(googletest
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    URL https://github.com/google/googletest/archive/refs/tags/release-1.11.0.zip
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
add_executable(mlkem src/ml-kem-test.cc)
target_link_libraries(mlkem GTest::gtest_main libcrux)
add_dependencies(mlkem libcrux)
