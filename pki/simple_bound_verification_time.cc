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
