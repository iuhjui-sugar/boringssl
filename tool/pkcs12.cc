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

#include <openssl/base.h>

#include <memory>
#include <string>
#include <vector>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#if defined(OPENSSL_WINDOWS)
#include <io.h>
#else
#include <unistd.h>
#endif

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs8.h>
#include <openssl/stack.h>

#include "../crypto/internal.h"
#include "internal.h"


static const struct argument kArguments[] = {
    {
     "-dump", kOptionalArgument,
     "Dump the key and contents of the given file to stdout",
    },
    {
     "", kOptionalArgument, "",
    },
};

bool DoPKCS12(const std::vector<std::string> &args) {
  std::map<std::string, std::string> args_map;

  if (!ParseKeyValueArguments(&args_map, args, kArguments) ||
      args_map["-dump"].empty()) {
    PrintUsage(kArguments);
    return false;
  }

  ScopedFD fd = OpenFD(args_map["-dump"].c_str(), O_RDONLY);
  if (!fd) {
    perror("open");
    return false;
  }

  struct stat st;
  if (fstat(fd.get(), &st)) {
    perror("fstat");
    return false;
  }
  const size_t size = st.st_size;

  std::unique_ptr<uint8_t[]> contents(new uint8_t[size]);
  size_t off = 0;
  while (off < size) {
    size_t bytes_read;
    if (!ReadFromFD(fd.get(), &bytes_read, contents.get() + off, size - off)) {
      perror("read");
      return false;
    }
    if (bytes_read == 0) {
      fprintf(stderr, "Unexpected EOF\n");
      return false;
    }
    off += bytes_read;
  }

  printf("Enter password: ");
  fflush(stdout);

  char password[256];
  off = 0;
  while (off < sizeof(password) - 1) {
    size_t bytes_read;
    if (!ReadFromFD(0, &bytes_read, password + off,
                    sizeof(password) - 1 - off)) {
      perror("read");
      return false;
    }

    off += bytes_read;
    if (bytes_read == 0 || OPENSSL_memchr(password, '\n', off) != nullptr) {
      break;
    }
  }

  char *newline = reinterpret_cast<char *>(OPENSSL_memchr(password, '\n', off));
  if (newline == NULL) {
    return false;
  }
  *newline = 0;

  CBS pkcs12;
  CBS_init(&pkcs12, contents.get(), size);

  EVP_PKEY *key;
  bssl::UniquePtr<STACK_OF(X509)> certs(sk_X509_new_null());

  if (!PKCS12_get_key_and_certs(&key, certs.get(), &pkcs12, password)) {
    fprintf(stderr, "Failed to parse PKCS#12 data:\n");
    ERR_print_errors_fp(stderr);
    return false;
  }
  bssl::UniquePtr<EVP_PKEY> key_owned(key);

  if (key != NULL) {
    PEM_write_PrivateKey(stdout, key, NULL, NULL, 0, NULL, NULL);
  }

  for (size_t i = 0; i < sk_X509_num(certs.get()); i++) {
    PEM_write_X509(stdout, sk_X509_value(certs.get(), i));
  }

  return true;
}
