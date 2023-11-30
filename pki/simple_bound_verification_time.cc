// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "simple_bound_verification_time.h"

namespace bssl {

SimpleBoundVerificationTime::SimpleBoundVerificationTime() = default;

SimpleBoundVerificationTime::~SimpleBoundVerificationTime() = default;

void SimpleBoundVerificationTime::TimeIsAtLeast(int64_t current_time) {
  int64_t observed_max = latest_time_seen_;
  while (observed_max < current_time) {
    if (latest_time_seen_.compare_exchange_strong(observed_max, current_time)) {
      break;
    }
    observed_max = latest_time_seen_;
  }
}

void SimpleBoundVerificationTime::ClearTimeBound(void) {
  latest_time_seen_ = INT64_MIN;
}

int64_t SimpleBoundVerificationTime::BoundTime(int64_t maybe_correct_time) {
  int64_t observed_max = latest_time_seen_;
  return (maybe_correct_time > observed_max) ? maybe_correct_time
                                             : observed_max;
}

}  // namespace bssl
