#include "path_service.h"

namespace bssl {

namespace fillins {

FilePath::FilePath() {}

FilePath::FilePath(const std::string& path)
    : path_(path) {}

const std::string& FilePath::value() const {
  return path_;
}

FilePath FilePath::AppendASCII(const std::string& ascii_path_element) const {
  return FilePath(path_ + "/" + ascii_path_element);
}

// static
void PathService::Get(PathKey key, FilePath *out) {
  // XXX fixme XXX
#if !defined(PKI_SRCDIR)
#define PKI_SRCDIR "/Users/bbe/boringssl/pki"
#endif
  *out = FilePath(PKI_SRCDIR);
}

}  // namespace fillins

}  // namespace bssl
