/* Copyright (c) 2015, Google Inc.
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

#ifndef OPENSSL_HEADER_CRYPTO_TEST_SCOPED_TYPES_H
#define OPENSSL_HEADER_CRYPTO_TEST_SCOPED_TYPES_H

#include <stdint.h>
#include <stdio.h>

#include <openssl/stack.h>
#include <openssl/x509.h>


template<typename StackType, typename T, void (*func)(T*)>
struct OpenSSLStackDeleter {
  void operator()(StackType *obj) {
    sk_pop_free(reinterpret_cast<_STACK*>(obj),
                reinterpret_cast<void (*)(void *)>(func));
  }
};

template<typename T>
struct OpenSSLFree {
  void operator()(T *buf) {
    OPENSSL_free(buf);
  }
};

struct FileCloser {
  void operator()(FILE *file) {
    fclose(file);
  }
};

template<typename StackType, typename T, void (*func)(T*)>
using ScopedOpenSSLStack =
    std::unique_ptr<StackType, OpenSSLStackDeleter<StackType, T, func>>;

using ScopedX509Stack = ScopedOpenSSLStack<STACK_OF(X509), X509, X509_free>;

using ScopedOpenSSLBytes = std::unique_ptr<uint8_t, OpenSSLFree<uint8_t>>;
using ScopedOpenSSLString = std::unique_ptr<char, OpenSSLFree<char>>;

using ScopedFILE = std::unique_ptr<FILE, FileCloser>;

#endif  // OPENSSL_HEADER_CRYPTO_TEST_SCOPED_TYPES_H
