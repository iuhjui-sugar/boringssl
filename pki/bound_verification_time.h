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

// Bound verification time values based on observed valid times to prevent time
// going back into the past. with anything like a regular update of the observed
// time from a trusted source this effectively implements a clock that does not
// go backwards, and updates infrequently. When given one good value at startup
// or from running with a good system clock, this prevents the system clock from
// being stepped back into the past to affect certificate validation in a
// negative way.

#ifndef BSSL_BOUND_VERIFICATION_TIME_H_
#define BSSL_BOUND_VERIFICATION_TIME_H_

#include <optional>

namespace bssl {

// A BoundVerificationTime records observed time values as posix times.  It is
// then used to bind times used for X.509 validation to be no less than the
// maximum observed time.
//
// TimeIsAtLeast should observe the time whenever when we obtain a time from a
// trusted source. This might be from an update server, from an SCT, from a
// roughtime server, or anything else that might convince us that it we trust it
// is telling us the truth that the world has reached at least a point in time,
// and we believe it.  Again this will bound all future certificate verification
// times to be at least the maximum value observed. It is safe to observe values
// that might be in the past with TimeIsAtLeast - they are ignored if a later
// observation exists.
//
// Effectively if you start with an trusted observation and times can be
// observed with something like reasonable regularity (daily - ish) you can
// probably run with the system clock permanently set to Jan 1 1970 and be close
// enough for most public web pki certificate validations. With something akin
// to roughtime or an update server updateing TimeIsAtLeast hourly we won't even
// miss certificate expiry by more than an hour or so, and we will not fail to
// validate certificates even with a totally bogus system time.
//

class OPENSSL_EXPORT BoundVerificationTime {
 public:
  virtual ~BoundVerificationTime() = default;
  // |TimeIsAtLeast| should be  called to store the result of a |current_time|
  // that we know to be less than or equal to the "correct" time.
  virtual void TimeIsAtLeast(int64_t current_time) = 0;

  // |ClearTimeBound| should be  called to reset the time lower bound. This will
  // have the effect that validations will then use the system time, until a
  // subsequent call to |TimeIsAtLeast| is made.
  virtual void ClearTimeBound(void) = 0;

  // if |TrustedTime| returns a value, it is assumed to be the exact time
  // as POSIX time value of seconds since the POSIX epoch to be used for
  // the validation time of an X.509 certificate. If no value is returned
  // |BoundTime| below is used.
  virtual std::optional<int64_t> TrustedTime(void) = 0;

  // |BoundTime| is called to get a validation time for an X.509 certificate. It
  // is passed a guess at the current time (frequently just the system time, but
  // we assume this is possibly fallable, manipulated, etc.)  BoundTime must
  // return the maximum of |maybe_correct_time| and the largest value so far
  // seen by any TimeIsAtLeast() calls. It returns |maybe_correct_time| if no
  // such calls have been made.
  virtual int64_t BoundTime(int64_t maybe_correct_time) = 0;
};

}  // namespace bssl

#endif  // BSSL_BOUND_VERIFICATION_TIME_H_
