#include "path_service.h"
#include <stdlib.h>

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
  char * pki_srcdir = getenv("PKI_SRCDIR");
  if (pki_srcdir != NULL)  {
    *out = FilePath(pki_srcdir);
  } else {
    *out = FilePath("/Users/bbe/boringssl/pki");
  }
}

}  // namespace fillins

}  // namespace bssl
