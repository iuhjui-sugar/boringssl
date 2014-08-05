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

#include "async_bio.h"

#include <errno.h>
#include <openssl/mem.h>

namespace {

extern const BIO_METHOD async_bio_method;

struct async_bio {
  size_t read_quota;
  size_t write_quota;
};

async_bio *get_data(BIO *b) {
  if (b->method != &async_bio_method) {
    return NULL;
  }
  return (async_bio *)b->ptr;
}

static int async_write(BIO *b, const char *in, int inl) {
  async_bio *a = get_data(b);
  if (a == NULL || b->next_bio == NULL) {
    return 0;
  }

  BIO_clear_retry_flags(b);

  if (a->write_quota == 0) {
    BIO_set_retry_write(b);
    errno = EAGAIN;
    return -1;
  }

  if ((size_t)inl > a->write_quota) {
    inl = a->write_quota;
  }
  int ret = BIO_write(b->next_bio, in, inl);
  if (ret <= 0) {
    BIO_copy_next_retry(b);
  } else {
    a->write_quota -= ret;
  }
  return ret;
}

static int async_read(BIO *b, char *out, int outl) {
  async_bio *a = get_data(b);
  if (a == NULL || b->next_bio == NULL) {
    return 0;
  }

  BIO_clear_retry_flags(b);

  if (a->read_quota == 0) {
    BIO_set_retry_read(b);
    errno = EAGAIN;
    return -1;
  }

  if ((size_t)outl > a->read_quota) {
    outl = a->read_quota;
  }
  int ret = BIO_read(b->next_bio, out, outl);
  if (ret <= 0) {
    BIO_copy_next_retry(b);
  } else {
    a->read_quota -= ret;
  }
  return ret;
}

static long async_ctrl(BIO *b, int cmd, long num, void *ptr) {
  if (b->next_bio == NULL) {
    return 0;
  }
  BIO_clear_retry_flags(b);
  int ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
  BIO_copy_next_retry(b);
  return ret;
}

static int async_new(BIO *b) {
  async_bio *a = (async_bio *)OPENSSL_malloc(sizeof(*a));
  if (a == NULL) {
    return 0;
  }
  memset(a, 0, sizeof(*a));
  b->init = 1;
  b->ptr = (char *)a;
  return 1;
}

static int async_free(BIO *b) {
  if (b == NULL) {
    return 0;
  }

  OPENSSL_free(b->ptr);
  b->ptr = NULL;
  b->init = 0;
  b->flags = 0;
  return 1;
}

static long async_callback_ctrl(BIO *b, int cmd, bio_info_cb fp) {
  long ret = 1;

  if (b->next_bio == NULL) {
    return 0;
  }

  switch (cmd) {
    default:
      ret = BIO_callback_ctrl(b->next_bio, cmd, fp);
      break;
  }
  return ret;
}

const BIO_METHOD async_bio_method = {
  BIO_TYPE_FILTER,
  "async bio",
  async_write,
  async_read,
  NULL /* puts */,
  NULL /* gets */,
  async_ctrl,
  async_new,
  async_free,
  async_callback_ctrl,
};

}  // namespace

BIO *async_bio_create() {
  return BIO_new(&async_bio_method);
}

void async_bio_allow_read(BIO *b, size_t bytes) {
  async_bio *a = get_data(b);
  if (a == NULL) {
    return;
  }
  a->read_quota += bytes;
}

void async_bio_allow_write(BIO *b, size_t bytes) {
  async_bio *a = get_data(b);
  if (a == NULL) {
    return;
  }
  a->write_quota += bytes;
}
