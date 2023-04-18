#include "file_util.h"

#include<string>
#include<fstream>
#include<iostream>
#include<streambuf>

namespace bssl {

namespace fillins {

bool ReadFileToString(const FilePath& path, std::string *out) {
  std::ifstream st(path.value());

  st.seekg(0, std::ios::end);
  if (st.tellg() < 0)
    return false;
  out->reserve(st.tellg());
  st.seekg(0, std::ios::beg);

  out->assign((std::istreambuf_iterator<char>(st)),
              std::istreambuf_iterator<char>());

  return true;
}

}  // namespace fillins

}  // namespace bssl
