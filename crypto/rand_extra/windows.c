/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <openssl/rand.h>

#if defined(OPENSSL_WINDOWS) && !defined(BORINGSSL_UNSAFE_DETERMINISTIC_MODE)

#include <limits.h>
#include <stdlib.h>
OPENSSL_MSVC_PRAGMA(warning(push, 3))

#if defined(WINAPI_FAMILY) && (WINAPI_FAMILY == WINAPI_FAMILY_APP)
#define WIN32_NO_STATUS  // need to define WIN32_NO_STATUS so that subsequent
#include <windows.h>     // winnt.h includes (via windows.h) will not result
#undef WIN32_NO_STATUS   // in re-definitions
#include <bcrypt.h>
#include <ntstatus.h>
OPENSSL_MSVC_PRAGMA(comment(lib, "bcrypt.lib"))
#else
#include <windows.h>

// #define needed to link in RtlGenRandom(), a.k.a. SystemFunction036.  See the
// "Community Additions" comment on MSDN here:
// http://msdn.microsoft.com/en-us/library/windows/desktop/aa387694.aspx
#define SystemFunction036 NTAPI SystemFunction036
#include <ntsecapi.h>
#undef SystemFunction036
#endif

OPENSSL_MSVC_PRAGMA(warning(pop))

#include "../fipsmodule/rand/internal.h"

void CRYPTO_sysrand(uint8_t *out, size_t requested) {
  while (requested > 0) {
    ULONG output_bytes_this_pass = ULONG_MAX;
    if (requested < output_bytes_this_pass) {
      output_bytes_this_pass = (ULONG)requested;
    }

#if defined(WINAPI_FAMILY) && (WINAPI_FAMILY == WINAPI_FAMILY_APP)
    if (BCryptGenRandom(
            NULL,  // Alg Handle pointer; NUll is passed as
                   // BCRYPT_USE_SYSTEM_PREFERRED_RNG flag is used
            out,   // Address of the buffer that recieves the random number(s)
            output_bytes_this_pass,  // Size of the buffer in bytes
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS) {
#else
    if (RtlGenRandom(out, output_bytes_this_pass) == FALSE) {
#endif
      abort();
    }
    requested -= output_bytes_this_pass;
    out += output_bytes_this_pass;
  }
  return;
}

#endif  // OPENSSL_WINDOWS && !BORINGSSL_UNSAFE_DETERMINISTIC_MODE
