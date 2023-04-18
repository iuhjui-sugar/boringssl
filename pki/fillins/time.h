#ifndef THIRDPARTY_CHROMIUM_CERTIFICATE_VERIFIER_FILLINS_TIME_H_
#define THIRDPARTY_CHROMIUM_CERTIFICATE_VERIFIER_FILLINS_TIME_H_
#include <openssl/base.h>

#include "../check.h"

namespace bssl {

namespace fillins {

// Represents an exploded time that can be formatted nicely. This is kind of
// like the Win32 SYSTEMTIME structure or the Unix "struct tm" with a few
// additions and changes to prevent errors.
struct OPENSSL_EXPORT Exploded {
  int year;          // Four digit year "2007"
  int month;         // 1-based month (values 1 = January, etc.)
  int unused_day_of_week;  // OK in struct literal, but not OK to use by name.
  int day_of_month;  // 1-based day of month (1-31)
  int hour;          // Hour within the current day (0-23)
  int minute;        // Minute within the current hour (0-59)
  int second;        // Second within the current minute (0-59 plus leap
                     //   seconds which may take it up to 60).
  int millisecond;   // Milliseconds within the current second (0-999)

  // A cursory test for whether the data members are within their
  // respective ranges. A 'true' return value does not guarantee the
  // Exploded value can be successfully converted to a Time value.
  OPENSSL_EXPORT bool HasValidValues() const;

  OPENSSL_EXPORT bool operator==(const Exploded& other) const {
    return year == other.year && month == other.month &&
           day_of_month == other.day_of_month && hour == other.hour &&
           minute == other.minute && second == other.second &&
           millisecond == other.millisecond;
  }
};

}  // namespace fillins

}  // namespace bssl

#endif  // THIRDPARTY_CHROMIUM_CERTIFICATE_VERIFIER_FILLINS_TIME_H_
