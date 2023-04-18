#include "third_party/chromium_certificate_verifier/fillins/string_split.h"

namespace bssl {

namespace fillins {

static const char kWhitespaceASCII[] = {
  0x09,    // CHARACTER TABULATION
  0x0A,    // LINE FEED (LF)
  0x0B,    // LINE TABULATION
  0x0C,    // FORM FEED (FF)
  0x0D,    // CARRIAGE RETURN (CR)
  0x20,    // SPACE
  0
};

absl::string_view TrimStringPieceT(absl::string_view input,
                                   absl::string_view trim_chars,
                                   TrimPositions positions) {
  size_t begin =
      (positions & TRIM_LEADING) ? input.find_first_not_of(trim_chars) : 0;
  if (begin == input.npos) {
    return input;
  }
  size_t end = (positions & TRIM_TRAILING)
                   ? input.find_last_not_of(trim_chars) + 1
                   : input.size();
  return input.substr(begin, end - begin);
}

static absl::string_view TrimString(absl::string_view input,
                                    const absl::string_view& trim_chars,
                                    TrimPositions positions) {
  return TrimStringPieceT(input, trim_chars, positions);
}

static void SplitStringUsingSubstrT(absl::string_view input,
                                    absl::string_view delimiter,
                                    WhitespaceHandling whitespace,
                                    SplitResult result_type,
                                    std::vector<absl::string_view>* result) {
  using size_type = typename absl::string_view::size_type;

  result->clear();
  for (size_type begin_index = 0, end_index = 0;
       end_index != absl::string_view::npos;
       begin_index = end_index + delimiter.size()) {
    end_index = input.find(delimiter, begin_index);
    absl::string_view term =
        end_index == absl::string_view::npos
            ? input.substr(begin_index)
            : input.substr(begin_index, end_index - begin_index);

    if (whitespace == TRIM_WHITESPACE) {
      term = TrimString(term, kWhitespaceASCII, TRIM_ALL);
    }

    if (result_type == SPLIT_WANT_ALL || !term.empty()) {
      result->push_back(term);
    }
  }
}

std::vector<absl::string_view> SplitStringPieceUsingSubstr(
    absl::string_view input, absl::string_view delimiter,
    WhitespaceHandling whitespace, SplitResult result_type) {
  std::vector<absl::string_view> result;
  SplitStringUsingSubstrT(input, delimiter, whitespace, result_type, &result);
  return result;
}

std::vector<std::string> SplitString(absl::string_view input,
                                     absl::string_view separators,
                                     WhitespaceHandling whitespace,
                                     SplitResult result_type) {
  std::vector<absl::string_view> parts;
  SplitStringUsingSubstrT(input, separators, whitespace, result_type, &parts);

  std::vector<std::string> result;
  for (auto const &part : parts) {
    result.push_back(std::string(part));
  }

  return result;
}

}  // namespace fillins

}  // namespace bssl
