OUTPUT_DIR=/usr/local/google/home/aknobloch/boringssl/build

rm -rf $OUTPUT_DIR/*
cmake -B build -DCMAKE_TOOLCHAIN_FILE=util/riscv-toolchain-clang.cmake -GNinja
ninja -C build