# Copyright (c) 2022, Google Inc.
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

# This script takes an existing FIPS build in build/ and recompiles it with
# each of the possible #defines for breaking a FIPS test.

set -x
set -e

DEFINES="INTEGRITY_TEST_FOR_KAT_TESTING ECDSA_PWCT RSA_PWCT CRNG"
HEADER="crypto/fipsmodule/break-fips-test.h"

if [ ! -d build ] ; then
  echo "This script should be run from the top-level of a BoringSSL checkout."
  echo "It expects a FIPS build to have been completed in the build/ directory."
  exit 1
fi

cp $HEADER $HEADER.orig

for define in $DEFINES; do
  sed -i -e "s/BORINGSSL_FIPS_BREAK_NOOP_PLACEHOLDER/BORINGSSL_FIPS_BREAK_$define/" crypto/fipsmodule/break-fips-test.h
  ninja -C build test_fips
  cp $HEADER.orig $HEADER

  mkdir -p out-$define
  cp build/util/fipstools/test_fips out-$define
done

rm $HEADER.orig
