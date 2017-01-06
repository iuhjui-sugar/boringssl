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

#include <string.h>

#include <openssl/bio.h>
#include <openssl/x509.h>

#include "../internal.h"


static bool TestPrint() {
  struct {
    const char *val, *want;
  } asn1_utctime_tests[] = {
    {"", "Bad time value"},

    // Correct RFC 5280 form. Test years < 2000 and > 2000.
    {"090303125425Z", "Mar  3 12:54:25 2009 GMT"},
    {"900303125425Z", "Mar  3 12:54:25 1990 GMT"},
    {"000303125425Z", "Mar  3 12:54:25 2000 GMT"},

    // Correct form, bad values.
    {"000000000000Z", "Bad time value"},
    {"999999999999Z", "Bad time value"},

    // Missing components.  Not legal RFC 5280, but permitted.
    {"090303125425", "Mar  3 12:54:25 2009"},
    {"9003031254", "Mar  3 12:54:00 1990"},

    // GENERALIZEDTIME confused for UTCTIME.
    {"20090303125425Z", "Bad time value"},

    // Legal ASN.1, but not legal RFC 5280.
    {"9003031254+0800", "Bad time value"},
    {"9003031254-0800", "Bad time value"},

    // Trailing garbage.
    {"9003031254Z ", "Bad time value"},
  };

  for (auto t : asn1_utctime_tests) {
    bssl::UniquePtr<ASN1_UTCTIME> tm(ASN1_UTCTIME_new());
    bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));

    // Use this instead of ASN1_UTCTIME_set(), because some callers get
    // type-confused and pass ASN1_GENERALIZEDTIME to ASN1_UTCTIME_print().
    // ASN1_UTCTIME_set_string() is stricter, and would reject the inputs in
    // question.
    if (!ASN1_STRING_set(tm.get(), t.val, strlen(t.val))) {
      fprintf(stderr, "ASN1_STRING_set\n");
      return false;
    }
    int result = !ASN1_UTCTIME_print(bio.get(), tm.get());
    const uint8_t *contents;
    size_t len;
    if (!BIO_mem_contents(bio.get(), &contents, &len)) {
      fprintf(stderr, "BIO_mem_contents\n");
      return false;
    }

    if (result != !strcmp(t.want, "Bad time value")) {
      fprintf(stderr, "ASN1_UTCTIME_print(%s): bad return value\n", t.val);
      return false;
    }
    if (len != strlen(t.want) || memcmp(contents, t.want, len)) {
      fprintf(stderr, "ASN1_UTCTIME_print(%s): got %.*s, want %s\n", t.val,
              static_cast<int>(len),
              reinterpret_cast<const char *>(contents), t.want);
      return false;
    }
  }
  return true;
}

int main() {
  if (!TestPrint()) {
    return 1;
  }

  printf("PASS\n");
  return 0;
}
