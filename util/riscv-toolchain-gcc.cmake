set(CMAKE_C_COMPILER "/usr/bin/riscv64-linux-gnu-gcc")
set(CMAKE_CXX_COMPILER "/usr/bin/riscv64-linux-gnu-g++")
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR "riscv64")

# Was trying to use this to resolve "can't find linker stuff" when building with clang
# set(CMAKE_SYSROOT "/usr/riscv64-linux-gnu/lib/")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -L/usr/riscv64-linux-gnu/lib/" CACHE STRING "c++ flags")
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -L/usr/riscv64-linux-gnu/lib/" CACHE STRING "c flags")
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -L/usr/riscv64-linux-gnu/lib/" CACHE STRING "asm flags")

# Old flags, for use with clang (I think...)
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --target=riscv64 -march=rv64gc" CACHE STRING "c++ flags")
# set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} --target=riscv64 -march=rv64gc" CACHE STRING "c flags")
# set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} --target=riscv64 -march=rv64gc" CACHE STRING "asm flags")