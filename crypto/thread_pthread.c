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

#include "internal.h"

#if defined(OPENSSL_PTHREADS)

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/mem.h>
#include <openssl/type_check.h>


OPENSSL_COMPILE_ASSERT(sizeof(CRYPTO_MUTEX) >= sizeof(pthread_rwlock_t),
                       CRYPTO_MUTEX_too_small);

void CRYPTO_MUTEX_init(CRYPTO_MUTEX *lock) {
  if (pthread_rwlock_init((pthread_rwlock_t *) lock, NULL) != 0) {
    abort();
  }
}

void CRYPTO_MUTEX_lock_read(CRYPTO_MUTEX *lock) {
  if (pthread_rwlock_rdlock((pthread_rwlock_t *) lock) != 0) {
    abort();
  }
}

void CRYPTO_MUTEX_lock_write(CRYPTO_MUTEX *lock) {
  if (pthread_rwlock_wrlock((pthread_rwlock_t *) lock) != 0) {
    abort();
  }
}

void CRYPTO_MUTEX_unlock_read(CRYPTO_MUTEX *lock) {
  if (pthread_rwlock_unlock((pthread_rwlock_t *) lock) != 0) {
    abort();
  }
}

void CRYPTO_MUTEX_unlock_write(CRYPTO_MUTEX *lock) {
  if (pthread_rwlock_unlock((pthread_rwlock_t *) lock) != 0) {
    abort();
  }
}

void CRYPTO_MUTEX_cleanup(CRYPTO_MUTEX *lock) {
  pthread_rwlock_destroy((pthread_rwlock_t *) lock);
}

void CRYPTO_STATIC_MUTEX_lock_read(struct CRYPTO_STATIC_MUTEX *lock) {
  if (pthread_rwlock_rdlock(&lock->lock) != 0) {
    abort();
  }
}

void CRYPTO_STATIC_MUTEX_lock_write(struct CRYPTO_STATIC_MUTEX *lock) {
  if (pthread_rwlock_wrlock(&lock->lock) != 0) {
    abort();
  }
}

void CRYPTO_STATIC_MUTEX_unlock_read(struct CRYPTO_STATIC_MUTEX *lock) {
  if (pthread_rwlock_unlock(&lock->lock) != 0) {
    abort();
  }
}

void CRYPTO_STATIC_MUTEX_unlock_write(struct CRYPTO_STATIC_MUTEX *lock) {
  if (pthread_rwlock_unlock(&lock->lock) != 0) {
    abort();
  }
}

void CRYPTO_once(CRYPTO_once_t *once, void (*init)(void)) {
  if (pthread_once(once, init) != 0) {
    abort();
  }
}

/* Used to create a linked list of all thread local data.  We need this so that
 * we can delete all data when the library is unloaded before the owning
 * threads call pthread_exit. */
typedef struct crypto_thread_local_data_st {
  /* Pointers to thread local data. */
  void *pointers[NUM_OPENSSL_THREAD_LOCALS];
  /* I like linked lists and I cannot lie. You other coders can't deny. */
  struct crypto_thread_local_data_st *prev, *next;
} CRYPTO_THREAD_LOCAL_DATA;

/* This should be locked whenever a thread is modifying or using the array of
 * destructors, or if a thread is changing the list of thread local data.  */
static pthread_mutex_t g_destructors_lock = PTHREAD_MUTEX_INITIALIZER;
static thread_local_destructor_t g_destructors[NUM_OPENSSL_THREAD_LOCALS];
static CRYPTO_THREAD_LOCAL_DATA *g_thread_local_data_list;

static CRYPTO_THREAD_LOCAL_DATA *create_local_data(void) {
  CRYPTO_THREAD_LOCAL_DATA *data = (CRYPTO_THREAD_LOCAL_DATA *)
      OPENSSL_malloc(sizeof(CRYPTO_THREAD_LOCAL_DATA));
  if (data == NULL) return NULL;
  OPENSSL_memset(data->pointers, 0, sizeof(void *) * NUM_OPENSSL_THREAD_LOCALS);
  if (pthread_mutex_lock(&g_destructors_lock) != 0) {
    return NULL;
  }
  if (g_thread_local_data_list) {
    g_thread_local_data_list->prev = data;
  }
  data->prev = NULL;
  data->next = g_thread_local_data_list;
  g_thread_local_data_list = data;
  pthread_mutex_unlock(&g_destructors_lock);
  return data;
}

/* Called by each thread on thread exit.  It releases thread local data for
 * that thread only. */
static void thread_local_destructor(void *arg) {
  if (arg == NULL) {
    return;
  }
  CRYPTO_THREAD_LOCAL_DATA *data = arg;
  thread_local_destructor_t destructors[NUM_OPENSSL_THREAD_LOCALS];
  if (pthread_mutex_lock(&g_destructors_lock) != 0) {
    return;
  }
  OPENSSL_memcpy(destructors, g_destructors, sizeof(destructors));
  if (data->next) {
    data->next->prev = data->prev;
  }
  if (data->prev) {
    data->prev->next = data->next;
  } else {
    g_thread_local_data_list = data->next;
  }
  pthread_mutex_unlock(&g_destructors_lock);

  unsigned i;
  for (i = 0; i < NUM_OPENSSL_THREAD_LOCALS; i++) {
    if (destructors[i] != NULL) {
      destructors[i](data->pointers[i]);
    }
  }
  OPENSSL_free(data);
}

static pthread_once_t g_thread_local_init_once = PTHREAD_ONCE_INIT;
static pthread_key_t g_thread_local_key;
static int g_thread_local_key_created = 0;

/* This is called when the library is unloaded via dlclose.  */
static void __attribute__((destructor)) delete_all_local_data(void) {
  if (g_thread_local_key_created) {
    int result = pthread_key_delete(g_thread_local_key);
    if (result) {
      /* This is run on library unload.  If the key delete fails,
       * there is not much we can do. */
    }
  }
  while (g_thread_local_data_list) {
    thread_local_destructor(g_thread_local_data_list);
  }
}

static void thread_local_init(void) {
  int result = pthread_key_create(&g_thread_local_key, thread_local_destructor);
  /* Possible errors: EAGAIN -> too many keys or other error.
   * ENOMEM -> out of memory. */
  g_thread_local_key_created = (result == 0);
}

void *CRYPTO_get_thread_local(thread_local_data_t index) {
  CRYPTO_once(&g_thread_local_init_once, thread_local_init);
  if (!g_thread_local_key_created) {
    return NULL;
  }

  CRYPTO_THREAD_LOCAL_DATA *data = pthread_getspecific(g_thread_local_key);
  if (data == NULL) {
    return NULL;
  }
  return data->pointers[index];
}

int CRYPTO_set_thread_local(thread_local_data_t index, void *value,
                            thread_local_destructor_t destructor) {
  CRYPTO_once(&g_thread_local_init_once, thread_local_init);
  if (!g_thread_local_key_created) {
    destructor(value);
    return 0;
  }

  CRYPTO_THREAD_LOCAL_DATA *data = pthread_getspecific(g_thread_local_key);
  if (data == NULL) {
    data = create_local_data();
    if (data == NULL) {
      destructor(value);
      return 0;
    }
    if (pthread_setspecific(g_thread_local_key, data) != 0) {
      thread_local_destructor(data);
      destructor(value);
      return 0;
    }
  }

  if (pthread_mutex_lock(&g_destructors_lock) != 0) {
    destructor(value);
    return 0;
  }
  g_destructors[index] = destructor;
  pthread_mutex_unlock(&g_destructors_lock);

  data->pointers[index] = value;
  return 1;
}

#endif  // OPENSSL_PTHREADS
