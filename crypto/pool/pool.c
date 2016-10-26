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

#include <openssl/pool.h>

#include <assert.h>
#include <string.h>

#include <openssl/bytestring.h>
#include <openssl/mem.h>
#include <openssl/thread.h>

#include "../internal.h"
#include "internal.h"


static uint32_t CRYPTO_BUFFER_hash(const CRYPTO_BUFFER *buf) {
  return OPENSSL_hash32(buf->data, buf->len);
}

static int CRYPTO_BUFFER_cmp(const CRYPTO_BUFFER *a, const CRYPTO_BUFFER *b) {
  if (a->len != b->len) {
    return 1;
  }
  return memcmp(a->data, b->data, a->len);
}

CRYPTO_BUFFER_POOL* CRYPTO_BUFFER_POOL_new(void) {
  CRYPTO_BUFFER_POOL *pool = OPENSSL_malloc(sizeof(CRYPTO_BUFFER_POOL));
  if (pool == NULL) {
    return NULL;
  }

  memset(pool, 0, sizeof(CRYPTO_BUFFER_POOL));
  pool->bufs = lh_CRYPTO_BUFFER_new(CRYPTO_BUFFER_hash, CRYPTO_BUFFER_cmp);
  if (pool->bufs == NULL) {
    free(pool);
    return NULL;
  }

  CRYPTO_MUTEX_init(&pool->lock);

  return pool;
}

void CRYPTO_BUFFER_POOL_free(CRYPTO_BUFFER_POOL *pool) {
  if (pool == NULL) {
    return;
  }

#if !defined(NDEBUG)
  CRYPTO_MUTEX_lock_write(&pool->lock);
  assert(lh_CRYPTO_BUFFER_num_items(pool->bufs) == 0);
  CRYPTO_MUTEX_unlock_write(&pool->lock);
#endif

  lh_CRYPTO_BUFFER_free(pool->bufs);
  CRYPTO_MUTEX_cleanup(&pool->lock);
  free(pool);
}

CRYPTO_BUFFER *CRYPTO_BUFFER_new(const uint8_t *data, size_t len,
                                 CRYPTO_BUFFER_POOL *pool) {
  if (pool != NULL) {
    CRYPTO_BUFFER tmp;
    tmp.data = (uint8_t *) data;
    tmp.len = len;

    CRYPTO_MUTEX_lock_read(&pool->lock);
    CRYPTO_BUFFER *const duplicate = lh_CRYPTO_BUFFER_retrieve(pool->bufs, &tmp);
    if (duplicate != NULL) {
      CRYPTO_refcount_inc(&duplicate->references);
    }
    CRYPTO_MUTEX_unlock_read(&pool->lock);

    if (duplicate != NULL) {
      return duplicate;
    }
  }

  CRYPTO_BUFFER *const buf = OPENSSL_malloc(sizeof(CRYPTO_BUFFER));
  if (buf == NULL) {
    return NULL;
  }
  memset(buf, 0, sizeof(CRYPTO_BUFFER));

  buf->data = OPENSSL_malloc(len);
  if (len != 0 && buf->data == NULL) {
    free(buf);
    return NULL;
  }

  buf->len = len;
  memcpy(buf->data, data, buf->len);

  if (pool == NULL) {
    buf->references = 1;
    return buf;
  }

  buf->references = 2;
  buf->pool = pool;

  CRYPTO_MUTEX_lock_write(&pool->lock);
  CRYPTO_BUFFER *duplicate = lh_CRYPTO_BUFFER_retrieve(pool->bufs, buf);
  CRYPTO_BUFFER *old;
  const int inserted =
      duplicate == NULL && lh_CRYPTO_BUFFER_insert(pool->bufs, &old, buf);
  assert(old == NULL);
  CRYPTO_MUTEX_unlock_write(&pool->lock);

  if (!inserted) {
    /* We raced to insert |buf| into the pool and lost, or else there was an
     * error inserting. */
    free(buf->data);
    free(buf);
    return duplicate;
  }

  return buf;
}

CRYPTO_BUFFER* CRYPTO_BUFFER_new_from_CBS(CBS *cbs, CRYPTO_BUFFER_POOL *pool) {
  return CRYPTO_BUFFER_new(CBS_data(cbs), CBS_len(cbs), pool);
}

void CRYPTO_BUFFER_free(CRYPTO_BUFFER *buf) {
  if (buf == NULL) {
    return;
  }

  CRYPTO_BUFFER_POOL *const pool = buf->pool;
  if (pool == NULL) {
    if (CRYPTO_refcount_dec_and_test_zero(&buf->references)) {
      /* If a reference count of zero is observed, there cannot be a reference
       * from any pool to this buffer and thus we are able to free this
       * buffer. */
      free(buf->data);
      free(buf);
    }

    return;
  }

  CRYPTO_MUTEX_lock_write(&pool->lock);
  CRYPTO_refcount_dec_and_test_zero(&buf->references);
  assert(buf->references >= 1);

  /* We have an exclusive lock on the pool, therefore no concurrent lookups can
   * find this buffer and increment the reference count. Thus, if the count is
   * one, the reference from the pool is the only reference and we can free
   * this buffer. */
  const int can_free = (buf->references == 1);
  if (can_free) {
    void *found = lh_CRYPTO_BUFFER_delete(pool->bufs, buf);
    assert(found != NULL);
    assert(found == buf);
  }
  CRYPTO_MUTEX_unlock_write(&buf->pool->lock);

  if (can_free) {
    free(buf->data);
    free(buf);
  }
}

int CRYPTO_BUFFER_up_ref(CRYPTO_BUFFER *buf) {
  CRYPTO_refcount_inc(&buf->references);
  return 1;
}

const uint8_t *CRYPTO_BUFFER_data(const CRYPTO_BUFFER *buf) {
  return buf->data;
}

const size_t CRYPTO_BUFFER_len(const CRYPTO_BUFFER *buf) {
  return buf->len;
}

void CRYPTO_BUFFER_init_CBS(const CRYPTO_BUFFER *buf, CBS *out) {
  CBS_init(out, buf->data, buf->len);
}
