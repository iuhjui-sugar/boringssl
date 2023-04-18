#include "utf_string_conversions.h"

#if 0
#include "third_party/icu/include/unicode/ucnv.h"
#include "third_party/icu/include/unicode/ustring.h"
#endif
namespace bssl {

namespace fillins {

#if 0
bool UTF16ToUTF8(const uint16_t *data, size_t num_chars, std::string* out) {
#if defined(OS_LINUX)
  static_assert(__BYTE_ORDER == __LITTLE_ENDIAN, "code assumes little-endian");
#elif defined(OS_MACOSX)
#if !defined(__LITTLE_ENDIAN__)
#error "code assumes little-endian"
#endif  // __LITTLE_ENDIAN__
#endif  // OS_MACOSX
  UErrorCode err = U_ZERO_ERROR;
  int32_t max_out_bytes;
  u_strToUTF8(nullptr, 0 /* buffer length */, &max_out_bytes,
              reinterpret_cast<const UChar*>(data), num_chars, &err);
  if (U_FAILURE(err) && err != U_BUFFER_OVERFLOW_ERROR) {
    return false;
  }

  std::unique_ptr<char[]> out_buf(new char[max_out_bytes]);
  int32_t bytes_filled;
  err = U_ZERO_ERROR;
  u_strToUTF8(out_buf.get(), max_out_bytes, &bytes_filled,
              reinterpret_cast<const UChar*>(data), num_chars, &err);
  if (U_FAILURE(err)) {
    return false;
  }
  out->assign(out_buf.get(), bytes_filled);
  return true;
}
#endif

static const size_t kMaxUTF8Bytes = 4;

static size_t EncodeUTF8(uint32_t codepoint, char *out_buf) {
  if (codepoint < 0x7f) {
    out_buf[0] = codepoint;
    return 1;
  }

  if (codepoint <= 0x7ff) {
    out_buf[0] = 0xc0 | (codepoint >> 6);
    out_buf[1] = 0x80 | (codepoint & 0x3f);
    return 2;
  }

  if (codepoint <= 0xffff) {
    out_buf[0] = 0xe0 | (codepoint >> 12);
    out_buf[1] = 0x80 | ((codepoint >> 6) & 0x3f);
    out_buf[2] = 0x80 | (codepoint & 0x3f);
    return 3;
  }

  out_buf[0] = 0xf0 | (codepoint >> 18);
  out_buf[1] = 0x80 | ((codepoint >> 12) & 0x3f);
  out_buf[2] = 0x80 | ((codepoint >> 6) & 0x3f);
  out_buf[3] = 0x80 | (codepoint & 0x3f);
  return 4;
}

void WriteUnicodeCharacter(uint32_t codepoint, std::string* append_to) {
  char buf[kMaxUTF8Bytes];
  const size_t num_bytes = EncodeUTF8(codepoint, buf);
  append_to->append(buf, num_bytes);
}

#if 0
bool ConvertToUtf8(const std::string& in, bool is_latin1, std::string* out) {
  if (!is_latin1) {
    return false;
  }

  UErrorCode err = U_ZERO_ERROR;
  UConverter* converter(ucnv_open("ISO-8859-1", &err));
  if (U_FAILURE(err)) {
    return false;
  }

  // A single byte in a legacy encoding can be expanded to 3 bytes in UTF-8.
  // A 'two-byte character' in a legacy encoding can be expanded to 4 bytes
  // in UTF-8. Therefore, the expansion ratio is 3 at most. Add one for a
  // trailing '\0'.
  size_t buf_length = in.length() * 3 + 1;
  std::unique_ptr<char[]> out_buf(new char[buf_length]);
  int32_t output_length =
      ucnv_toAlgorithmic(UCNV_UTF8, converter, out_buf.get(), buf_length,
                         in.data(), in.length(), &err);
  ucnv_close(converter);
  if (U_FAILURE(err)) {
    return false;
  }

  out->assign(out_buf.get(), output_length);
  return true;
}
#endif

}  // namespace fillins

}  // namespace bssl
