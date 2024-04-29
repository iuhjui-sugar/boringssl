/* Copyright (c) 2024, Google Inc.
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

#ifndef OPENSSL_HEADER_CRYPTO_BCM_SUPPORT_H
#define OPENSSL_HEADER_CRYPTO_BCM_SUPPORT_H

#if defined(__cplusplus)
extern "C" {
#endif

// Provided by libcrypto, called from BCM

#if defined(BORINGSSL_UNSAFE_DETERMINISTIC_MODE)
#define OPENSSL_RAND_DETERMINISTIC
#elif defined(OPENSSL_TRUSTY)
#define OPENSSL_RAND_TRUSTY
#elif defined(OPENSSL_WINDOWS)
#define OPENSSL_RAND_WINDOWS
#elif defined(OPENSSL_LINUX)
#define OPENSSL_RAND_URANDOM
#elif defined(OPENSSL_APPLE) && !defined(OPENSSL_MACOS)
// Unlike macOS, iOS and similar hide away getentropy().
#define OPENSSL_RAND_IOS
#else
// By default if you are integrating BoringSSL we expect you to
// provide getentropy from the <unistd.h> header file.
#define OPENSSL_RAND_GETENTROPY
#endif

#if defined(__cplusplus)
extern "C" {
#endif

// Provided by libcrypto, called from BCM

// CRYPTO_init_sysrand initializes long-lived resources needed to draw entropy
// from the operating system, if the operating system requires initialization.
void CRYPTO_init_sysrand(void);

// CRYPTO_sysrand fills |len| bytes at |buf| with entropy from the operating
// system.
void CRYPTO_sysrand(uint8_t *buf, size_t len);

// CRYPTO_sysrand_if_available fills |len| bytes at |buf| with entropy from the
// operating system, or early /dev/urandom data, and returns 1, _if_ the entropy
// pool is initialized or if getrandom() is not available and not in FIPS mode.
// Otherwise it will not block and will instead fill |buf| with all zeros and
// return 0.
int CRYPTO_sysrand_if_available(uint8_t *buf, size_t len);

// CRYPTO_sysrand_for_seed fills |len| bytes at |buf| with entropy from the
// operating system. It may draw from the |GRND_RANDOM| pool on Android,
// depending on the vendor's configuration.
void CRYPTO_sysrand_for_seed(uint8_t *buf, size_t len);

// RAND_need_entropy is called whenever the BCM module has stopped because it
// has run out of entropy.
void RAND_need_entropy(size_t bytes_needed);

<<<<<<< HEAD
// RAND_load_entropy supplies |entropy_len| bytes of entropy to the BCM
// module. The |want_additional_input| parameter is true iff the entropy was
// obtained from a source other than the system, e.g. directly from the CPU.
void RAND_load_entropy(const uint8_t *entropy, size_t entropy_len,
                       int want_additional_input);
=======
// crypto_get_fork_generation returns the fork generation number for the current
// process, or zero if not supported on the platform. The fork generation number
// is a non-zero, strictly-monotonic counter with the property that, if queried
// in an address space and then again in a subsequently forked copy, the forked
// address space will observe a greater value.
//
// This function may be used to clear cached values across a fork. When
// initializing a cache, record the fork generation. Before using the cache,
// check if the fork generation has changed. If so, drop the cache and update
// the save fork generation. Note this logic transparently handles platforms
// which always return zero.
//
// This is not reliably supported on all platforms which implement |fork|, so it
// should only be used as a hardening measure.
OPENSSL_EXPORT uint64_t CRYPTO_get_fork_generation(void);

// CRYPTO_fork_detect_force_madv_wipeonfork_for_testing is an internal detail
// used for testing purposes.
OPENSSL_EXPORT void CRYPTO_fork_detect_force_madv_wipeonfork_for_testing(
    int on);

>>>>>>> 3e3597b31 (derp)

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CRYPTO_BCM_SUPPORT_H
