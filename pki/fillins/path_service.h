#ifndef EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_PATH_SERVICE_H
#define EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_PATH_SERVICE_H

#include <string>

namespace bssl {

namespace fillins {

class FilePath {
 public:
  FilePath();
  FilePath(const std::string& path);

  const std::string& value() const;

  FilePath AppendASCII(const std::string &ascii_path_element) const;

 private:
  std::string path_;
};

enum PathKey {
  DIR_SOURCE_ROOT = 0,
};

class PathService {
 public:
  static void Get(PathKey key, FilePath *out);
};

}  // namespace fillins

}  // namespace bssl

#endif  // EXPERIMENTAL_USERS_AGL_LIBSLEEVI_FILLINS_PATH_SERVICE_H
