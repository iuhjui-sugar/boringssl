#include "time.h"

namespace bssl {
namespace fillins {

inline bool is_in_range(int value, int lo, int hi) {
  return lo <= value && value <= hi;
}

bool fillins::Exploded::HasValidValues() const {
  // The range (0, 60) derives from upstream.  I assume that it is to handle
  // leap seconds in UTC.
  return is_in_range(month, 1, 12) && is_in_range(day_of_month, 1, 31) &&
         is_in_range(hour, 0, 23) && is_in_range(minute, 0, 59) &&
         is_in_range(second, 0, 60) && is_in_range(millisecond, 0, 999);
}

}  // namespace fillins
}  // namespace bssl
