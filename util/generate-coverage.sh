#!/bin/sh
set -xe

SRC=$PWD

BUILD=$(mktemp -d '/tmp/boringssl.XXXXXX')
BUILD_SRC=$(mktemp -d '/tmp/boringssl-src.XXXXXX')
LCOV=$(mktemp -d '/tmp/boringssl-lcov.XXXXXX')

cd "$BUILD"
cmake "$SRC" -GNinja -DCMAKE_C_FLAGS='-fprofile-arcs -ftest-coverage' -DCMAKE_CXX_FLAGS='-fprofile-arcs -ftest-coverage' -DCMAKE_ASM_FLAGS='-Wa,-g'
ninja

cp -r $SRC/crypto $SRC/decrepit $SRC/include $SRC/ssl $SRC/tool $BUILD_SRC
cp -r $BUILD/* $BUILD_SRC
mkdir "$BUILD/callgrind/"

cd "$SRC"
go run "$SRC/util/all_tests.go" -build-dir "$BUILD" -callgrind || true
util/generate-asm-lcov.py "$BUILD/callgrind" "$BUILD" > "$BUILD/asm.info"

go run "util/all_tests.go" -build-dir "$BUILD"

cd "$SRC/ssl/test/runner"
go test -shim-path "$BUILD/ssl/test/bssl_shim" -num-workers 1

cd "$LCOV"
lcov -c -d "$BUILD" -b "$BUILD" -o "$BUILD/lcov.info"
lcov -r "$BUILD/lcov.info" "*_test.c" -o "$BUILD/lcov-1.info"
lcov -r "$BUILD/lcov-1.info" "*_test.cc" -o "$BUILD/lcov-2.info"
cat "$BUILD/lcov-2.info" "$BUILD/asm.info" > "$BUILD/final.info"
sed -i "s;$BUILD;$BUILD_SRC;g" "$BUILD/final.info"
sed -i "s;$SRC;$BUILD_SRC;g" "$BUILD/final.info"
genhtml -p "$BUILD_SRC" "$BUILD/final.info"
xdg-open index.html
