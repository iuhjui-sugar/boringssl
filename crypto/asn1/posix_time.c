/* Copyright (c) 2022, Google Inc.
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

//
// Time coversion to/from POSIX time_t from struct tm, with no support
// for time zones other than UTC
//
#include <sys/errno.h>

#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <time.h>

#include "internal.h"

#define SECS_PER_HOUR (60 * 60)
#define SECS_PER_DAY (24 * SECS_PER_HOUR)

// Inspired by algorithms presented in
// http://howardhinnant.github.io/date_algorithms.html
// (Public Domain)
static int64_t posix_time_from_utc(int32_t year, uint32_t month, uint32_t day,
                                   uint32_t hours, uint32_t minutes,
                                   uint32_t seconds) {
  if (month <= 2)
    year--;  // Start years on Mar 1, so leap days always finish a year.
  int64_t era = (year >= 0 ? year : year - 399) / 400;
  uint32_t year_of_era = year - era * 400;
  uint32_t day_of_year =
      (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1;
  uint32_t day_of_era =
      year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
  int64_t posix_days = era * 146097 + day_of_era - 719468;
  int64_t posix_time = posix_days * SECS_PER_DAY + hours * SECS_PER_HOUR +
                       minutes * 60 + seconds;

  return posix_time;
}

// Inspired by algorithms presented in
// http://howardhinnant.github.io/date_algorithms.html
// (Public Domain)
static void utc_from_posix_time(time_t time, int32_t *out_year,
                                uint32_t *out_month, uint32_t *out_day,
                                uint32_t *out_hours, uint32_t *out_minutes,
                                uint32_t *out_seconds) {
  int64_t days = time / SECS_PER_DAY;
  int64_t leftover_seconds = time % SECS_PER_DAY;
  if (leftover_seconds < 0) {
    days--;
    leftover_seconds += SECS_PER_DAY;
  }
  days += 719468;  // Shift to starting Mar 1 0000
  int64_t era = (days > 0 ? days : days - 146096) / 146097;
  uint32_t day_of_era = days - era * 146097;
  uint32_t year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36524 -
                          day_of_era / 146096) /
                         365;
  *out_year = year_of_era + era * 400;  // Year starting Mar 1.
  uint32_t day_of_year =
      day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
  uint32_t month_of_year = (5 * day_of_year + 2) / 153;
  *out_month = month_of_year < 10 ? month_of_year + 3 : month_of_year - 9;
  if (*out_month <= 2) {
    (*out_year)++;  // Adjust back to Jan 1 start of year.
  }
  *out_day = day_of_year - (153 * month_of_year + 2) / 5 + 1;
  *out_hours = leftover_seconds / SECS_PER_HOUR;
  leftover_seconds -= *out_hours * SECS_PER_HOUR;
  *out_minutes = leftover_seconds / 60;
  *out_seconds = leftover_seconds % 60;
}

static int is_valid_date(int year, int month, int day) {
  if (day < 1 || month < 1 || year < 0 ||  year > 9999) {
    return 0;
  }
  switch (month) {
    case 1:
    case 3:
    case 5:
    case 7:
    case 8:
    case 10:
    case 12:
      return day > 0 && day <= 31;
    case 4:
    case 6:
    case 9:
    case 11:
      return day > 0 && day <= 30;
    case 2:
      if ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0) {
        return day > 0 && day <= 29;
      } else {
        return day > 0 && day <= 28;
      }
    default:
      return 0;
  }
}

static int is_valid_time(int hours, int minutes, int seconds) {
  if (hours < 0 || minutes < 0 || seconds < 0 || hours > 23 || minutes > 59 ||
      seconds > 59) {
    return 0;
  }
  return 1;
}

// Convert a UTC date in a tm to posix time, restricting ourselves to
// years 0 to 9999 as is applicable to X.509 ASN.1 times. If my
// DeLorean with the flux capacitor takes me to year 9999 and X.509 is
// still in use, I'm coming back and kidnapping myself to another
// better timeline before I land this.
//
// Unlike "standard" timegm() (which is in no way standard), we do not
// support any offsets in the tm but UTC, and we do not support dates
// outside of the years 0000 to 9999.
//
// If time_t is integer sized, we return -1 and set errno to EOVERFLOW
// if the value is not representable in an integer sized time_t.
time_t OPENSSL_timegm(struct tm *tm) {
  if (!is_valid_date(tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday) ||
      !is_valid_time(tm->tm_hour, tm->tm_min, tm->tm_sec)) {
    return -1;
  }
  int64_t posix_time =
      posix_time_from_utc(tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                          tm->tm_hour, tm->tm_min, tm->tm_sec);

  if (sizeof(time_t) == sizeof(int) && (posix_time > INT_MAX ||
                                        posix_time < INT_MIN)) {
    errno = EOVERFLOW;
    return -1;
  }
  return posix_time;
}

// Convert a time_t to a tm value as long as the tm value lies in the
// years 0 to 9999 which are applicable to X.509 ASN.1 times.
struct tm *OPENSSL_gmtime(const time_t *time, struct tm *out_tm) {
#if defined(OPENSSL_64_BIT)
  // Bound the time_t we will care about between 0000 and 9999
  if (*time < -62167219200)  // 0000-01-01 00:00:00 UTC
    return NULL;
  if (*time > 253402300799)  // 9999-12-31 23:59:59 UTC
    return NULL;
#endif
  memset(out_tm, 0, sizeof(struct tm));
  utc_from_posix_time(*time, (int32_t *)&out_tm->tm_year,
                      (uint32_t *)&out_tm->tm_mon, (uint32_t *)&out_tm->tm_mday,
                      (uint32_t *)&out_tm->tm_hour, (uint32_t *)&out_tm->tm_min,
                      (uint32_t *)&out_tm->tm_sec);

  out_tm->tm_year -= 1900;
  out_tm->tm_mon -= 1;

  return out_tm;
}
