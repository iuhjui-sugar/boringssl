/* Copyright (c) 2016, Google Inc.
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

#include <vector>

#include <assert.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/pem.h>

#include "../test/scoped_types.h"


static const char kCrossSigningRootPEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICcTCCAdqgAwIBAgIIagJHiPvE0MowDQYJKoZIhvcNAQELBQAwPDEaMBgGA1UE\n"
"ChMRQm9yaW5nU1NMIFRFU1RJTkcxHjAcBgNVBAMTFUNyb3NzLXNpZ25pbmcgUm9v\n"
"dCBDQTAgFw0xNTAxMDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowPDEaMBgGA1UE\n"
"ChMRQm9yaW5nU1NMIFRFU1RJTkcxHjAcBgNVBAMTFUNyb3NzLXNpZ25pbmcgUm9v\n"
"dCBDQTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwo3qFvSB9Zmlbpzn9wJp\n"
"ikI75Rxkatez8VkLqyxbOhPYl2Haz8F5p1gDG96dCI6jcLGgu3AKT9uhEQyyUko5\n"
"EKYasazSeA9CQrdyhPg0mkTYVETnPM1W/ebid1YtqQbq1CMWlq2aTDoSGAReGFKP\n"
"RTdXAbuAXzpCfi/d8LqV13UCAwEAAaN6MHgwDgYDVR0PAQH/BAQDAgIEMB0GA1Ud\n"
"JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAPBgNVHRMBAf8EBTADAQH/MBkGA1Ud\n"
"DgQSBBBHKHC7V3Z/3oLvEZx0RZRwMBsGA1UdIwQUMBKAEEcocLtXdn/egu8RnHRF\n"
"lHAwDQYJKoZIhvcNAQELBQADgYEAnglibsy6mGtpIXivtlcz4zIEnHw/lNW+r/eC\n"
"CY7evZTmOoOuC/x9SS3MF9vawt1HFUummWM6ZgErqVBOXIB4//ykrcCgf5ZbF5Hr\n"
"+3EFprKhBqYiXdD8hpBkrBoXwn85LPYWNd2TceCrx0YtLIprE2R5MB2RIq8y4Jk3\n"
"YFXvkME=\n"
"-----END CERTIFICATE-----\n";

static const char kRootCAPEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICVTCCAb6gAwIBAgIIAj5CwoHlWuYwDQYJKoZIhvcNAQELBQAwLjEaMBgGA1UE\n"
"ChMRQm9yaW5nU1NMIFRFU1RJTkcxEDAOBgNVBAMTB1Jvb3QgQ0EwIBcNMTUwMTAx\n"
"MDAwMDAwWhgPMjEwMDAxMDEwMDAwMDBaMC4xGjAYBgNVBAoTEUJvcmluZ1NTTCBU\n"
"RVNUSU5HMRAwDgYDVQQDEwdSb290IENBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB\n"
"iQKBgQDpDn8RDOZa5oaDcPZRBy4CeBH1siSSOO4mYgLHlPE+oXdqwI/VImi2XeJM\n"
"2uCFETXCknJJjYG0iJdrt/yyRFvZTQZw+QzGj+mz36NqhGxDWb6dstB2m8PX+plZ\n"
"w7jl81MDvUnWs8yiQ/6twgu5AbhWKZQDJKcNKCEpqa6UW0r5nwIDAQABo3oweDAO\n"
"BgNVHQ8BAf8EBAMCAgQwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMA8G\n"
"A1UdEwEB/wQFMAMBAf8wGQYDVR0OBBIEEEA31wH7QC+4HH5UBCeMWQEwGwYDVR0j\n"
"BBQwEoAQQDfXAftAL7gcflQEJ4xZATANBgkqhkiG9w0BAQsFAAOBgQDXylEK77Za\n"
"kKeY6ZerrScWyZhrjIGtHFu09qVpdJEzrk87k2G7iHHR9CAvSofCgEExKtWNS9dN\n"
"+9WiZp/U48iHLk7qaYXdEuO07No4BYtXn+lkOykE+FUxmA4wvOF1cTd2tdj3MzX2\n"
"kfGIBAYhzGZWhY3JbhIfTEfY1PNM1pWChQ==\n"
"-----END CERTIFICATE-----\n";

static const char kRootCrossSignedPEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICYzCCAcygAwIBAgIIAj5CwoHlWuYwDQYJKoZIhvcNAQELBQAwPDEaMBgGA1UE\n"
"ChMRQm9yaW5nU1NMIFRFU1RJTkcxHjAcBgNVBAMTFUNyb3NzLXNpZ25pbmcgUm9v\n"
"dCBDQTAgFw0xNTAxMDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowLjEaMBgGA1UE\n"
"ChMRQm9yaW5nU1NMIFRFU1RJTkcxEDAOBgNVBAMTB1Jvb3QgQ0EwgZ8wDQYJKoZI\n"
"hvcNAQEBBQADgY0AMIGJAoGBAOkOfxEM5lrmhoNw9lEHLgJ4EfWyJJI47iZiAseU\n"
"8T6hd2rAj9UiaLZd4kza4IURNcKSckmNgbSIl2u3/LJEW9lNBnD5DMaP6bPfo2qE\n"
"bENZvp2y0Habw9f6mVnDuOXzUwO9SdazzKJD/q3CC7kBuFYplAMkpw0oISmprpRb\n"
"SvmfAgMBAAGjejB4MA4GA1UdDwEB/wQEAwICBDAdBgNVHSUEFjAUBggrBgEFBQcD\n"
"AQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zAZBgNVHQ4EEgQQQDfXAftAL7gc\n"
"flQEJ4xZATAbBgNVHSMEFDASgBBHKHC7V3Z/3oLvEZx0RZRwMA0GCSqGSIb3DQEB\n"
"CwUAA4GBAErTxYJ0en9HVRHAAr5OO5wuk5Iq3VMc79TMyQLCXVL8YH8Uk7KEwv+q\n"
"9MEKZv2eR/Vfm4HlXlUuIqfgUXbwrAYC/YVVX86Wnbpy/jc73NYVCq8FEZeO+0XU\n"
"90SWAPDdp+iL7aZdimnMtG1qlM1edmz8AKbrhN/R3IbA2CL0nCWV\n"
"-----END CERTIFICATE-----\n";

static const char kIntermediatePEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICXjCCAcegAwIBAgIJAKJMH+7rscPcMA0GCSqGSIb3DQEBCwUAMC4xGjAYBgNV\n"
"BAoTEUJvcmluZ1NTTCBURVNUSU5HMRAwDgYDVQQDEwdSb290IENBMCAXDTE1MDEw\n"
"MTAwMDAwMFoYDzIxMDAwMTAxMDAwMDAwWjA2MRowGAYDVQQKExFCb3JpbmdTU0wg\n"
"VEVTVElORzEYMBYGA1UEAxMPSW50ZXJtZWRpYXRlIENBMIGfMA0GCSqGSIb3DQEB\n"
"AQUAA4GNADCBiQKBgQC7YtI0l8ocTYJ0gKyXTtPL4iMJCNY4OcxXl48jkncVG1Hl\n"
"blicgNUa1r9m9YFtVkxvBinb8dXiUpEGhVg4awRPDcatlsBSEBuJkiZGYbRcAmSu\n"
"CmZYnf6u3aYQ18SU8WqVERPpE4cwVVs+6kwlzRw0+XDoZAczu8ZezVhCUc6NbQID\n"
"AQABo3oweDAOBgNVHQ8BAf8EBAMCAgQwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsG\n"
"AQUFBwMCMA8GA1UdEwEB/wQFMAMBAf8wGQYDVR0OBBIEEIwaaKi1dttdV3sfjRSy\n"
"BqMwGwYDVR0jBBQwEoAQQDfXAftAL7gcflQEJ4xZATANBgkqhkiG9w0BAQsFAAOB\n"
"gQCvnolNWEHuQS8PFVVyuLR+FKBeUUdrVbSfHSzTqNAqQGp0C9fk5oCzDq6ZgTfY\n"
"ESXM4cJhb3IAnW0UM0NFsYSKQJ50JZL2L3z5ZLQhHdbs4RmODGoC40BVdnJ4/qgB\n"
"aGSh09eQRvAVmbVCviDK2ipkWNegdyI19jFfNP5uIkGlYg==\n"
"-----END CERTIFICATE-----\n";

static const char kLeafPEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICXjCCAcegAwIBAgIIWjO48ufpunYwDQYJKoZIhvcNAQELBQAwNjEaMBgGA1UE\n"
"ChMRQm9yaW5nU1NMIFRFU1RJTkcxGDAWBgNVBAMTD0ludGVybWVkaWF0ZSBDQTAg\n"
"Fw0xNTAxMDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowMjEaMBgGA1UEChMRQm9y\n"
"aW5nU1NMIFRFU1RJTkcxFDASBgNVBAMTC2V4YW1wbGUuY29tMIGfMA0GCSqGSIb3\n"
"DQEBAQUAA4GNADCBiQKBgQDD0U0ZYgqShJ7oOjsyNKyVXEHqeafmk/bAoPqY/h1c\n"
"oPw2E8KmeqiUSoTPjG5IXSblOxcqpbAXgnjPzo8DI3GNMhAf8SYNYsoH7gc7Uy7j\n"
"5x8bUrisGnuTHqkqH6d4/e7ETJ7i3CpR8bvK16DggEvQTudLipz8FBHtYhFakfdh\n"
"TwIDAQABo3cwdTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEG\n"
"CCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwGQYDVR0OBBIEEKN5pvbur7mlXjeMEYA0\n"
"4nUwGwYDVR0jBBQwEoAQjBpoqLV2211Xex+NFLIGozANBgkqhkiG9w0BAQsFAAOB\n"
"gQBj/p+JChp//LnXWC1k121LM/ii7hFzQzMrt70bny406SGz9jAjaPOX4S3gt38y\n"
"rhjpPukBlSzgQXFg66y6q5qp1nQTD1Cw6NkKBe9WuBlY3iYfmsf7WT8nhlT1CttU\n"
"xNCwyMX9mtdXdQicOfNjIGUCD5OLV5PgHFPRKiHHioBAhg==\n"
"-----END CERTIFICATE-----\n";

// CertFromPEM parses the given, NUL-terminated PEM block and returns an
// |X509*|.
static X509* CertFromPEM(const char *pem) {
  ScopedBIO bio(BIO_new_mem_buf(const_cast<char*>(pem), strlen(pem)));
  return PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
}

// CertsToStack converts a vector of |X509*| to an OpenSSL STACK_OF(X509*),
// bumping the reference counts for each certificate in question.
static STACK_OF(X509)* CertsToStack(const std::vector<X509*> &certs) {
  ScopedX509Stack stack(sk_X509_new_null());
  for (auto cert : certs) {
    if (!sk_X509_push(stack.get(), cert)) {
      return nullptr;
    }
    X509_up_ref(cert);
  }

  return stack.release();
}

static bool Verify(X509 *leaf, const std::vector<X509 *> &roots,
                   const std::vector<X509 *> &intermediates,
                   unsigned long flags = 0) {
  ScopedX509Stack roots_stack(CertsToStack(roots));
  ScopedX509Stack intermediates_stack(CertsToStack(intermediates));
  if (!roots_stack ||
      !intermediates_stack) {
    return false;
  }

  ScopedX509_STORE_CTX ctx(X509_STORE_CTX_new());
  if (!ctx) {
    return false;
  }
  if (!X509_STORE_CTX_init(ctx.get(), nullptr /* no X509_STORE */, leaf,
                           intermediates_stack.get())) {
    return false;
  }

  X509_STORE_CTX_trusted_stack(ctx.get(), roots_stack.get());

  X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
  if (param == nullptr) {
    return false;
  }
  X509_VERIFY_PARAM_set_time(param, 1452807555 /* Jan 14th, 2016 */);
  X509_VERIFY_PARAM_set_depth(param, 16);
  if (flags) {
    X509_VERIFY_PARAM_set_flags(param, flags);
  }
  X509_STORE_CTX_set0_param(ctx.get(), param);

  ERR_clear_error();
  return X509_verify_cert(ctx.get()) == 1;
}

int main(int argc, char **argv) {
  ScopedX509 cross_signing_root(CertFromPEM(kCrossSigningRootPEM));
  ScopedX509 root(CertFromPEM(kRootCAPEM));
  ScopedX509 root_cross_signed(CertFromPEM(kRootCrossSignedPEM));
  ScopedX509 intermediate(CertFromPEM(kIntermediatePEM));
  ScopedX509 leaf(CertFromPEM(kLeafPEM));

  if (!cross_signing_root ||
      !root ||
      !root_cross_signed ||
      !intermediate ||
      !leaf) {
    fprintf(stderr, "Failed to parse certificates\n");
    return 1;
  }

  if (Verify(leaf.get(), {}, {})) {
    fprintf(stderr, "Leaf verified with no roots!\n");
    return 1;
  }

  if (Verify(leaf.get(), {}, {intermediate.get()})) {
    fprintf(stderr, "Leaf verified with no roots!\n");
    return 1;
  }

  if (!Verify(leaf.get(), {root.get()}, {intermediate.get()})) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "Basic chain didn't verify.\n");
    return 1;
  }

  if (!Verify(leaf.get(), {cross_signing_root.get()},
              {intermediate.get(), root_cross_signed.get()})) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "Cross-signed chain didn't verify.\n");
    return 1;
  }

  if (!Verify(leaf.get(), {cross_signing_root.get(), root.get()},
              {intermediate.get(), root_cross_signed.get()})) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "Cross-signed chain with root didn't verify.\n");
    return 1;
  }

  /* This is the “altchains” test – we remove the cross-signing CA but include
   * the cross-sign in the intermediates. */
  if (!Verify(leaf.get(), {root.get()},
              {intermediate.get(), root_cross_signed.get()})) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "Chain with cross-sign didn't backtrack to find root.\n");
    return 1;
  }

  if (Verify(leaf.get(), {root.get()},
             {intermediate.get(), root_cross_signed.get()},
             X509_V_FLAG_NO_ALT_CHAINS)) {
    fprintf(stderr, "Altchains test still passed when disabled.\n");
    return 1;
  }

  printf("PASS\n");
  return 0;
}
