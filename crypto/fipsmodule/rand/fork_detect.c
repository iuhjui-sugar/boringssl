/* Copyright (c) 2020, Google Inc.
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

#if defined(OPENSSL_LINUX) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE  // needed for madvise() and MAP_ANONYMOUS on Linux.
#endif

#include <openssl/base.h>
#include "fork_detect.h"

#if !defined(OPENSSL_FORK_DETECTION)

#if defined(OPENSSL_DOES_NOT_FORK)
// This platform has promised it never duplicates address space like |fork|
// does. Therefore we do not need to re-seed calls to |RAND_bytes| to prevent
// address space duplication from causing random value re-use. Returning a
// constant value of 1 has this effect.
uint64_t CRYPTO_get_fork_generation(void) { return 1; }

#else
// This platform has NOT promised it never duplicates address space like |fork|
// does. However, we do not have a mechanism we believe can detect address space
// duplication reliably. Returning a constant value of 0 will ensure we re-seed
// on every call to |RAND_bytes|, so that duplicate address spaces will not
// re-use the same random values.
uint64_t CRYPTO_get_fork_generation(void) { return 0; }

#endif

#else // OPENSSL_FORK_DETECTION
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>

#include <pthread.h>

#if defined(OPENSSL_FORK_DETECTION_MADVISE)
#include <sys/mman.h>
#if defined(MADV_WIPEONFORK)
static_assert(MADV_WIPEONFORK == 18, "MADV_WIPEONFORK is not 18");
#else
#define MADV_WIPEONFORK 18
#endif
#endif // OPENSSL_FORK_DETECTION_MADVISE

#include "../delocate.h"
#include "../../internal.h"

DEFINE_BSS_GET(int, g_force_madv_wipeonfork);
DEFINE_BSS_GET(int, g_force_madv_wipeonfork_enabled);
#if defined(OPENSSL_FORK_DETECTION_MADVISE)
DEFINE_STATIC_ONCE(g_fork_detect_once);
DEFINE_STATIC_MUTEX(g_fork_detect_lock);
DEFINE_BSS_GET(CRYPTO_atomic_u32 *, g_fork_detect_addr);
DEFINE_BSS_GET(uint64_t, g_fork_generation);
#endif

pthread_once_t pthread_fork_detection_once = PTHREAD_ONCE_INIT;
uint32_t atfork_fork_generation = 1;

static void we_are_forked(void) {
  atfork_fork_generation++;
  if (atfork_fork_generation == 0) {
    atfork_fork_generation++;
  }
}

static void init_pthread_fork_detection(void) {
  if (pthread_atfork(NULL, NULL, we_are_forked) != 0) {
    abort();
  }
}

#if defined(OPENSSL_FORK_DETECTION_MADVISE)
static void init_fork_detect(void) {
  if (*g_force_madv_wipeonfork_bss_get()) {
    return;
  }

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) {
    return;
  }

  void *addr = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (addr == MAP_FAILED) {
    return;
  }

  // Some versions of qemu (up to at least 5.0.0-rc4, see linux-user/syscall.c)
  // ignore |madvise| calls and just return zero (i.e. success). But we need to
  // know whether MADV_WIPEONFORK actually took effect. Therefore try an invalid
  // call to check that the implementation of |madvise| is actually rejecting
  // unknown |advice| values.
  if (madvise(addr, (size_t)page_size, -1) == 0 ||
      madvise(addr, (size_t)page_size, MADV_WIPEONFORK) != 0) {
    munmap(addr, (size_t)page_size);
    return;
  }

  CRYPTO_atomic_store_u32(addr, 1);
  *g_fork_detect_addr_bss_get() = addr;
  *g_fork_generation_bss_get() = 1;

}
#endif // OPENSSL_FORK_DETECTION_MADVISE

uint64_t CRYPTO_get_fork_generation(void) {
  if (pthread_once(&pthread_fork_detection_once, init_pthread_fork_detection) != 0) {
    abort();
  }
  // At a minimum, we consider the generation from pthread_atfork. This should
  // be good enough on most POSIX style platforms without extensive use of
  // address space cloning mechanisms that are not detected by pthread_atfork.
  // We return a generation number that is the sum of the the 32 bit atfork
  // generation and 32 bit MADVISE generation number, skipping 0.
  uint64_t ret = atfork_fork_generation;

#if defined( OPENSSL_FORK_DETECTION_MADVISE)
  CRYPTO_once(g_fork_detect_once_bss_get(), init_fork_detect);

  // In a single-threaded process, there are obviously no races because there's
  // only a single mutator in the address space.
  //
  // In a multi-threaded environment, |CRYPTO_once| ensures that the flag byte
  // is initialised atomically, even if multiple threads enter this function
  // concurrently.
  //
  // Additionally, while the kernel will only clear WIPEONFORK at a point when a
  // child process is single-threaded, the child may become multi-threaded
  // before it observes this. Therefore, we must synchronize the logic below.

  CRYPTO_atomic_u32 *const flag_ptr = *g_fork_detect_addr_bss_get();
  if (flag_ptr == NULL) {
    // Our kernel is too old to support |MADV_WIPEONFORK| or
    // |g_force_madv_wipeonfork| is set.
    if (*g_force_madv_wipeonfork_bss_get() &&
        *g_force_madv_wipeonfork_enabled_bss_get()) {
      // A constant generation number to simulate support, even if the kernel
      // doesn't support it.
      return 42;
    }
    // return our best effort. if the kernel doesn't support MADV_WIPEONFORK
    // we still return the generation number from atfork.
    return ret;
  }

  // In the common case, try to observe the flag without taking a lock. This
  // avoids cacheline contention in the PRNG.
  uint32_t *const generation_ptr = g_fork_generation_bss_get();
  if (CRYPTO_atomic_load_u32(flag_ptr) != 0) {
    // If we observe a non-zero flag, it is safe to read |generation_ptr|
    // without a lock. The flag and generation number are fixed for this copy of
    // the address space.
    return ret + *generation_ptr;
  }

  // The flag was zero. The generation number must be incremented, but other
  // threads may have concurrently observed the zero, so take a lock before
  // incrementing.
  struct CRYPTO_STATIC_MUTEX *const lock = g_fork_detect_lock_bss_get();
  CRYPTO_STATIC_MUTEX_lock_write(lock);
  uint32_t current_generation = *generation_ptr;
  if (CRYPTO_atomic_load_u32(flag_ptr) == 0) {
    // A fork has occurred.
    current_generation++;

    // We must update |generation_ptr| before |flag_ptr|. Other threads may
    // observe |flag_ptr| without taking a lock.
    *generation_ptr = current_generation;
    CRYPTO_atomic_store_u32(flag_ptr, 1);
  }
  ret += current_generation;
  CRYPTO_STATIC_MUTEX_unlock_write(lock);

#endif  // OPENSSL_FORK_DETECTION_MADVISE

  return ret;
}

void CRYPTO_fork_detect_force_madv_wipeonfork_for_testing(int on) {
  *g_force_madv_wipeonfork_bss_get() = 1;
  *g_force_madv_wipeonfork_enabled_bss_get() = on;
}

#endif  // OPENSSL_FORK_DETECTION
