// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

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

  void ClearTimeBound(void) override;

  int64_t BoundTime(int64_t maybe_correct_time) override;

 private:
  std::atomic<int64_t> latest_time_seen_;
};

}  // namespace bssl

#endif  // BSSL_SIMPLE_BOUND_VERIFICATION_TIME_H_
