#ifndef BSSL_FILLINS_UTF_STRING_CONVERSIONS
#define BSSL_FILLINS_UTF_STRING_CONVERSIONS
#include <openssl/base.h>

#include <string>


namespace bssl {

namespace fillins {

#define CBU_IS_SURROGATE(c) (((c)&0xfffff800) == 0xd800)

#define CBU_IS_UNICODE_NONCHAR(c)                                          \
  ((c) >= 0xfdd0 && ((uint32_t)(c) <= 0xfdef || ((c)&0xfffe) == 0xfffe) && \
   (uint32_t)(c) <= 0x10ffff)

#define CBU_IS_UNICODE_CHAR(c)                             \
  ((uint32_t)(c) < 0xd800 ||                               \
   ((uint32_t)(c) > 0xdfff && (uint32_t)(c) <= 0x10ffff && \
    !CBU_IS_UNICODE_NONCHAR(c)))

// bool UTF16ToUTF8(const uint16_t *data, size_t num_chars, std::string* out);

OPENSSL_EXPORT void WriteUnicodeCharacter(uint32_t codepoint,
                                          std::string *append_to);

// bool ConvertToUtf8(const std::string& in, bool is_latin1, std::string* out);

}  // namespace fillins

}  // namespace bssl

#endif  // BSSL_FILLINS_UTF_STRING_CONVERSIONS
