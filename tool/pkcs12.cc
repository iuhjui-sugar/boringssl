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

#include <memory>
#include <string>
#include <vector>

#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bytestring.h>
#include <openssl/pem.h>
#include <openssl/pkcs8.h>
#include <openssl/stack.h>

#include "internal.h"


static const struct argument kArguments[] = {
    {
     "-dump", false, "Dump the key and contents of the given file to stdout",
    },
    {
     "", false, "",
    },
};

bool PKCS12(const std::vector<std::string> &args) {
  std::map<std::string, std::string> args_map;

  if (!ParseKeyValueArguments(&args_map, args, kArguments) ||
      args_map["-dump"].empty()) {
    PrintUsage(kArguments);
    return false;
  }

  int fd = open(args_map["-dump"].c_str(), O_RDONLY);
  if (fd < 0) {
    perror("open");
    return false;
  }

  struct stat st;
  if (fstat(fd, &st)) {
    perror("fstat");
    close(fd);
    return false;
  }
  const size_t size = st.st_size;

  std::unique_ptr<uint8_t[]> contents(new uint8_t[size]);
  ssize_t n;
  size_t off = 0;
  do {
    n = read(fd, &contents[off], size - off);
    if (n >= 0) {
      off += static_cast<size_t>(n);
    }
  } while ((n > 0 && off < size) || (n == -1 && errno == EINTR));

  if (off != size) {
    perror("read");
    close(fd);
    return false;
  }

  close(fd);

  printf("Enter password: ");
  fflush(stdout);

  char password[256];
  off = 0;
  do {
    n = read(0, &password[off], sizeof(password) - 1 - off);
    if (n >= 0) {
      off += static_cast<size_t>(n);
    }
  } while ((n > 0 && memchr(password, '\n', off) == NULL &&
            off < sizeof(password) - 1) ||
           (n == -1 && errno == EINTR));

  char *newline = reinterpret_cast<char*>(memchr(password, '\n', off));
  if (newline == NULL) {
    return false;
  }
  *newline = 0;

  CBS pkcs12;
  CBS_init(&pkcs12, contents.get(), size);

  EVP_PKEY *key;
  STACK_OF(X509) *certs = sk_X509_new_null();

  if (!PKCS12_get_key_and_certs(&key, certs, &pkcs12, password)) {
    fprintf(stderr, "Failed to parse PKCS#12 data:\n");
    BIO_print_errors_fp(stderr);
    return false;
  }

  PEM_write_PrivateKey(stdout, key, NULL, NULL, 0, NULL, NULL);
  EVP_PKEY_free(key);

  for (size_t i = 0; i < sk_X509_num(certs); i++) {
    PEM_write_X509(stdout, sk_X509_value(certs, i));
  }
  sk_X509_pop_free(certs, X509_free);

  return true;
}
