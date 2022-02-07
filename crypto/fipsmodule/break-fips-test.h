// Copyright (c) 2022, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#ifndef OPENSSL_HEADER_CRYPTO_BREAK_FIPS_TESTS_H
#define OPENSSL_HEADER_CRYPTO_BREAK_FIPS_TESTS_H


// This header is deliberately a no-op. During FIPS testing, BoringSSL is
// compiled with the useless define below replaced by various
// |BORINGSSL_FIPS_BREAK_*| values in order to show that some of the tests are
// effective. This does not apply to known-answer tests, which are broken by
// `util/fipstools/break-kat.go`, which rewrites the input value for the test in
// the compiled binary itself.

#define BORINGSSL_FIPS_BREAK_NOOP_PLACEHOLDER


#endif // OPENSSL_HEADER_CRYPTO_BREAK_FIPS_TESTS_H
