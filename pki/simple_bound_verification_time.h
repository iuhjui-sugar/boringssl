/* Copyright (c) 2023, Google Inc.
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

#ifndef BSSL_SIMPLE_BOUND_VERIFICATION_TIME_H_
#define BSSL_SIMPLE_BOUND_VERIFICATION_TIME_H_

#include <atomic>

#include <openssl/base.h>
#include "bound_verification_time.h"

namespace bssl {

// SimpleBoundVerificationTime is an implementation of BoundVerificationTime. It
// uses atomic operations to maintin a lower bound on a clock value for the time
// at which we will verify X.509 certificates.

class OPENSSL_EXPORT SimpleBoundVerificationTime
    : public BoundVerificationTime {
 public:
  SimpleBoundVerificationTime();

  ~SimpleBoundVerificationTime() override;

  void TimeIsAtLeast(int64_t current_time) override;

  std::optional<int64_t> TrustedTime(void) override;

  void ClearTimeBound(void) override;

  int64_t BoundTime(int64_t maybe_correct_time) override;

 private:
  std::atomic<int64_t> latest_time_seen_;
};

}  // namespace bssl

#endif  // BSSL_SIMPLE_BOUND_VERIFICATION_TIME_H_
