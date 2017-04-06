/* Copyright (c) 2017, Google Inc.
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

#ifndef OPENSSL_HEADER_FIPSMODULE_DELOCATE_H
#define OPENSSL_HEADER_FIPSMODULE_DELOCATE_H

#include <openssl/base.h>

#include "../internal.h"


#if defined(BORINGSSL_FIPS)

/* NONMODULE_RODATA, in FIPS mode, causes delocate.go to move the specified
 * const global to the unhashed non-module area of code located after the
 * module. */
#define NONMODULE_RODATA __attribute__((section("nonmodule_rodata")))

/* NONMODULE_TEXT, in FIPS mode, causes delocate.go to move the specified
 * function to the unhashed non-module area of code located after the module. */
#define NONMODULE_TEXT __attribute__((section("nonmodule_text")))

/* DEFINE_METHOD_FUNCTION defines a function named |name| which returns a method
 * table of type const |type|*, initialized by |initializer|. In FIPS mode, to
 * avoid rel.ro data, it is split into a static initializer in the module and a
 * unhashed, non-module accessor function to space reserved in the BSS. See
 * FIPS.md for more details.
 *
 * __VA_ARGS__ is used to get around macros not allowing arguments with
 * commas. */
#define DEFINE_METHOD_FUNCTION(type, name, ... /* initializer */) \
  static NONMODULE_TEXT type *name##_bss_get(void) {               \
    static type ret;                                              \
    return &ret;                                                  \
  }                                                               \
                                                                  \
  __attribute__((constructor)) static void name##_init(void) {    \
    type ret = __VA_ARGS__;                                       \
    OPENSSL_memcpy(name##_bss_get(), &ret, sizeof(ret));          \
  }                                                               \
                                                                  \
  const type *name(void) { return name##_bss_get(); }

#else /* !BORINGSSL_FIPS */

#define NONMODULE_RODATA
#define NONMODULE_TEXT
#define DEFINE_METHOD_FUNCTION(type, name, ...) \
  const type *name(void) {                      \
    static const type ret = __VA_ARGS__;        \
    return &ret;                                \
  }

#endif /* BORINGSSL_FIPS */

#endif /* OPENSSL_HEADER_FIPSMODULE_DELOCATE_H */
