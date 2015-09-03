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

#if !defined(OPENSSL_WINDOWS)

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <openssl/thread.h>
#include <openssl/mem.h>

#include "internal.h"
#include "../internal.h"


/* This file implements a PRNG by reading from /dev/urandom, optionally with a
 * buffer, which is dangerously unsafe across |fork|.  To use it, the caller
 * must promise never to fork. */

#define BUF_SIZE 4096

/* rand_buffer contains unused, random bytes, some of which may have been
 * consumed already. */
struct rand_buffer {
  size_t used;
  uint8_t rand[BUF_SIZE];
};

static struct CRYPTO_STATIC_MUTEX global_lock = CRYPTO_STATIC_MUTEX_INIT;

/* urandom_fd is a file descriptor to /dev/urandom. It's protected by
 * |global_lock|. */
static int urandom_fd = -2;

/* urandom_buffering controls whether buffering is enabled (1) or not (0). This
 * is protected by |global_lock|. */
static int urandom_buffering = 0;

/* urandom_get_fd_locked returns a file descriptor to /dev/urandom. The caller
 * of this function must hold |global_lock|. */
static int urandom_get_fd_locked(void) {
  if (urandom_fd != -2) {
    return urandom_fd;
  }

  do {
    urandom_fd = open("/dev/urandom", O_RDONLY);
  } while (urandom_fd == -1 && errno == EINTR);
  return urandom_fd;
}

/* RAND_cleanup close any cached file descriptor. */
void RAND_cleanup(void) {
  CRYPTO_STATIC_MUTEX_lock_write(&global_lock);
  if (urandom_fd >= 0) {
    close(urandom_fd);
  }
  urandom_fd = -2;
  CRYPTO_STATIC_MUTEX_unlock(&global_lock);
  /* Don't touch thread-local storage.  That's got its own cleanup
   * mechanism. */
}

void RAND_set_urandom_fd(int fd) {
  CRYPTO_STATIC_MUTEX_lock_write(&global_lock);
  if (urandom_fd != -2) {
    /* |RAND_set_urandom_fd| may not be called after the RNG is used. */
    abort();
  }
  do {
    urandom_fd = dup(fd);
  } while (urandom_fd == -1 && errno == EINTR);
  if (urandom_fd < 0) {
    abort();
  }
  CRYPTO_STATIC_MUTEX_unlock(&global_lock);
}

void RAND_I_promise_not_to_fork(void) {
  CRYPTO_STATIC_MUTEX_lock_write(&global_lock);
  urandom_buffering = 1;
  CRYPTO_STATIC_MUTEX_unlock(&global_lock);
}

static struct rand_buffer *get_thread_local_buffer(void) {
  struct rand_buffer *buf =
      CRYPTO_get_thread_local(OPENSSL_THREAD_LOCAL_URANDOM_BUF);
  if (buf == NULL) {
    buf = (struct rand_buffer *) OPENSSL_malloc(sizeof(struct rand_buffer));
    if (buf == NULL) {
      abort();
    }
    buf->used = BUF_SIZE;  /* To trigger a |read_full| on first use. */
    CRYPTO_set_thread_local(OPENSSL_THREAD_LOCAL_URANDOM_BUF, buf,
                            OPENSSL_free);
  }
  return buf;
}

/* read_full reads exactly |len| bytes from |fd| into |out| and returns 1. In
 * the case of an error it returns 0. */
static char read_full(int fd, uint8_t *out, size_t len) {
  ssize_t r;

  while (len > 0) {
    do {
      r = read(fd, out, len);
    } while (r == -1 && errno == EINTR);

    if (r <= 0) {
      return 0;
    }
    out += r;
    len -= r;
  }

  return 1;
}

/* Puts |requested| random bytes from the buffer into |out|.  Acquires its own
 * locks. */
static void read_from_buffer(uint8_t *out, size_t requested) {
  struct rand_buffer *buf = get_thread_local_buffer();
  size_t remaining = BUF_SIZE - buf->used;

  if (requested > remaining) {
    /* Open urandom and loop until the buffer has enough bytes that we can fall
     * through to the fast path. */
    CRYPTO_STATIC_MUTEX_lock_write(&global_lock);
    int fd = urandom_get_fd_locked();
    if (fd < 0) {
      CRYPTO_STATIC_MUTEX_unlock(&global_lock);
      abort();
      return;
    }
    CRYPTO_STATIC_MUTEX_unlock(&global_lock);

    while (requested > remaining) {
      memcpy(out, &buf->rand[buf->used], remaining);
      buf->used += remaining;
      out += remaining;
      requested -= remaining;

      if (!read_full(fd, buf->rand, BUF_SIZE)) {
        abort();
        return;
      }
      buf->used = 0;
      remaining = BUF_SIZE;
    }
  }

  memcpy(out, &buf->rand[buf->used], requested);
  buf->used += requested;
}

/* CRYPTO_sysrand puts |requested| random bytes into |out|. */
void CRYPTO_sysrand(uint8_t *out, size_t requested) {
  if (requested == 0) {
    return;
  }

  CRYPTO_STATIC_MUTEX_lock_read(&global_lock);  /* read |urandom_buffering| */
  if (urandom_buffering) {
    CRYPTO_STATIC_MUTEX_unlock(&global_lock);
    read_from_buffer(out, requested);
  } else {
    CRYPTO_STATIC_MUTEX_unlock(&global_lock);  /* can't upgrade lock */

    CRYPTO_STATIC_MUTEX_lock_write(&global_lock);
    int fd = urandom_get_fd_locked();
    if (fd < 0) {
      CRYPTO_STATIC_MUTEX_unlock(&global_lock);
      abort();
      return;
    }
    CRYPTO_STATIC_MUTEX_unlock(&global_lock);

    if (!read_full(fd, out, requested)) {
      abort();
    }
  }
}

#endif  /* !OPENSSL_WINDOWS */
