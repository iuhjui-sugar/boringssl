#!/bin/sh
# Copyright (c) 2016, Google Inc.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

set -xe

usage="Usage: $(basename "$0") [-l dir] [--arch (32|64)] [-t binary]\
 [-a args]"

SRC=$PWD

BUILD=$(mktemp -d '/tmp/boringssl.XXXXXX')
BUILD_SRC=$(mktemp -d '/tmp/boringssl-src.XXXXXX')
LCOV=$(mktemp -d '/tmp/boringssl-lcov.XXXXXX')

if [[ $# == 1 ]]; then
  echo $usage
  exit 1
fi

while [[ $# > 1 ]]
do
  case $1 in
    -l|--lcov)
      LCOV=$(readlink -f "$2")
      mkdir -p "$LCOV"
      shift
      ;;
    --arch)
      if [ "$2" == "32" ]; then
        BUILD_FLAGS="-DCMAKE_TOOLCHAIN_FILE='util/32-bit-toolchain.cmake'"
      fi
      shift
      ;;
    -t|--test)
      TEST="$2"
      shift
      ;;
    -a|--args)
      TEST_ARGS="$2"
      shift
      ;;
    *)
      echo $usage
      exit 1
      ;;
  esac
  shift
done

cd "$BUILD"
cmake "$SRC" -GNinja -DCALLGRIND=1 $BUILD_FLAGS
ninja

cp -r "$SRC/crypto" "$SRC/decrepit" "$SRC/include" "$SRC/ssl" "$SRC/tool" \
  "$BUILD_SRC"
cp -r "$BUILD"/* "$BUILD_SRC"
mkdir "$BUILD/callgrind/"

if [ -n "$TEST" ]; then
  cd "$BUILD"
  TEST=$(readlink -f "$TEST")
  cd "$SRC"
  valgrind -q --tool=callgrind \
    --callgrind-out-file="$BUILD/callgrind/callgrind.out.%p" \
    --dump-instr=yes --collect-jumps=yes $TEST $TEST_ARGS
  $TEST $TEST_ARGS
else
  cd "$SRC"
  go run "$SRC/util/all_tests.go" -build-dir "$BUILD" -callgrind \
    -num-workers 16
  go run "util/all_tests.go" -build-dir "$BUILD"
  cd "$SRC/ssl/test/runner"
  go test -shim-path "$BUILD/ssl/test/bssl_shim" -num-workers 1
fi

cd "$SRC"
util/generate-asm-lcov.py "$BUILD/callgrind" "$BUILD" > "$BUILD/asm.info"

cd "$LCOV"
lcov -c -d "$BUILD" -b "$BUILD" -o "$BUILD/lcov.info"
lcov -r "$BUILD/lcov.info" "*_test.c" -o "$BUILD/lcov-1.info"
lcov -r "$BUILD/lcov-1.info" "*_test.cc" -o "$BUILD/lcov-2.info"
cat "$BUILD/lcov-2.info" "$BUILD/asm.info" > "$BUILD/final.info"
sed -i "s;$BUILD;$BUILD_SRC;g" "$BUILD/final.info"
sed -i "s;$SRC;$BUILD_SRC;g" "$BUILD/final.info"
genhtml -p "$BUILD_SRC" "$BUILD/final.info"

rm -rf "$BUILD"
rm -rf "$BUILD_SRC"

xdg-open index.html
