ANDROID_NDK=/usr/local/google/home/aknobloch/android-ndk-r28-canary
OUTPUT_DIR=/usr/local/google/home/aknobloch/boringssl/build

rm -rf $OUTPUT_DIR/*
cmake -DANDROID_ABI=riscv64 \
      -DANDROID_PLATFORM=android-35 \
      -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK}/build/cmake/android.toolchain.cmake \
      -GNinja -B build

ninja -C build