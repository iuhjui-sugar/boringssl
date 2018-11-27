/* Copyright (c) 2018, Google Inc.
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

#if defined(OPENSSL_LINUX) && !defined(BORINGSSL_SHARED_LIBRARY)

#include <functional>
#include <utility>
#include <vector>

#include <sys/syscall.h>
#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <openssl/aead.h>
#include <openssl/cpu.h>
#include <openssl/mem.h>

#include <gtest/gtest.h>

#include "internal.h"


// Breakpoint uses Linux perf events to install a hardware breakpoint that
// triggers if code at the given address is executed.
class Breakpoint {
 public:
  explicit Breakpoint(const void *function_address) {
    struct perf_event_attr event;
    OPENSSL_memset(&event, 0, sizeof(event));
    event.type = PERF_TYPE_BREAKPOINT;
    event.size = sizeof(event);
    event.bp_type = HW_BREAKPOINT_X;
    event.bp_addr = reinterpret_cast<uintptr_t>(function_address);
    event.bp_len = sizeof(long);
    event.exclude_kernel = 1;
    event.exclude_hv = 1;


    fd_ = NewPerfEvent(&event, 0 /* this process */,
                       -1 /* running on any CPU core */,
                       -1 /* no perf-event group */, 0 /* flags */);
    if (fd_ < 0) {
      abort();
    }
  }

  Breakpoint(Breakpoint &&other) {
    fd_ = other.fd_;
    other.fd_ = -1;
  }

  ~Breakpoint() {
    if (fd_ != -1) {
      close(fd_);
    }
  }

  bool HasBeenHit() {
    uint64_t count;
    if (read(fd_, &count, sizeof(count)) != sizeof(uint64_t)) {
      abort();
    }
    return count != 0;
  }

 private:
  Breakpoint() = delete;
  Breakpoint(const Breakpoint&) = delete;

  static long NewPerfEvent(struct perf_event_attr *hw_event, pid_t pid, int cpu,
                           int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
  }

  int fd_ = -1;
};

template<typename T> const void *Func(T func) {
  static_assert(std::is_function<typename std::remove_pointer<T>::type>::value);
  return reinterpret_cast<const char *>(func);
}

class ImplDispatchTest : public ::testing::Test {
 protected:
  // AssertBreakpoints takes a list of pairs of code addresses and booleans, and
  // a function to test. It runs the given function and asserts, for each code
  // address, that the boolean reflects whether that address was executed or
  // not.
  void AssertBreakpoints(
      std::vector<std::pair<const void *, bool>> breakpoint_funcs,
      std::function<void()> f) {
    std::vector<Breakpoint> breakpoints;
    for (auto &breakpoint : breakpoint_funcs) {
      breakpoints.emplace_back(breakpoint.first);
    }

    f();

    for (size_t i = 0; i < breakpoint_funcs.size(); i++) {
      SCOPED_TRACE(i);
      EXPECT_EQ(breakpoint_funcs[i].second, breakpoints[i].HasBeenHit());
    }
  }
};

#if defined(OPENSSL_X86_64)

extern "C" {
int CRYPTO_gcm128_encrypt_ctr32(void *ctx, const void *key, const uint8_t *in,
                                uint8_t *out, size_t len, void *stream);
size_t aesni_gcm_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                         const void *key, uint8_t ivec[16], uint64_t *Xi);
void aes_hw_encrypt(const uint8_t *in, uint8_t *out, const void *key);
void aes_hw_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t len,
                                 const void *key, const uint8_t ivec[16]);
}

TEST_F(ImplDispatchTest, AESNI) {
  const bool avx_movbe = ((OPENSSL_ia32cap_get()[1] >> 22) & 0x41) == 0x41;

  AssertBreakpoints(
      {
          {Func(CRYPTO_gcm128_encrypt_ctr32), true},
          {Func(aes_hw_ctr32_encrypt_blocks), true},
          {Func(aes_hw_encrypt), true},
          {Func(aesni_gcm_encrypt), avx_movbe},
      },
      [] {
        const uint8_t kZeros[16] = {0};
        const uint8_t kPlaintext[40] = {1, 2, 3, 4, 0};
        uint8_t ciphertext[sizeof(kPlaintext) + 16];
        size_t ciphertext_len;
        EVP_AEAD_CTX ctx;
        ASSERT_TRUE(EVP_AEAD_CTX_init(&ctx, EVP_aead_aes_128_gcm(), kZeros,
                                      sizeof(kZeros),
                                      EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr));
        ASSERT_TRUE(EVP_AEAD_CTX_seal(
            &ctx, ciphertext, &ciphertext_len, sizeof(ciphertext), kZeros,
            EVP_AEAD_nonce_length(EVP_aead_aes_128_gcm()), kPlaintext,
            sizeof(kPlaintext), nullptr, 0));
      });
}

#endif  // X86_64

#endif  // LINUX && !SHARED_LIBRARY
