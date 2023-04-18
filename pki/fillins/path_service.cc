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
#if defined(_BORINGSSL_PKI_SRCDIR_)
  // We stringify the compile parameter because cmake. sigh.
#define _boringssl_xstr(s) _boringssl_str(s)
#define _boringssl_str(s) #s
  char pki_srcdir[] = _boringssl_xstr(_BORINGSSL_PKI_SRCDIR_);
#else
#error "No _BORINGSSL_PKI_SRCDIR
#endif // defined(BORINGSSL_PKI_SRCDIR
    *out = FilePath(pki_srcdir);
}

}  // namespace fillins

}  // namespace bssl
