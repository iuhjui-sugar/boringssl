// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "path_service.h"

#include <stdlib.h>
#include <filesystem>
#include <iostream>

namespace bssl {

namespace {

bool path_exists(const char *path) {
  std::filesystem::directory_entry entry(path);
  return entry.exists();
}

}  // namespace

namespace fillins {

FilePath::FilePath() {}

FilePath::FilePath(const std::string &path) : path_(path) {}

const std::string &FilePath::value() const { return path_; }

FilePath FilePath::AppendASCII(const std::string &ascii_path_element) const {
  // Append a path element to a path. Use the \ separator if this appears to
  // be a Windows path, otherwise the Unix one.
  if (path_.find(":\\") != std::string::npos) {
    return FilePath(path_ + "\\" + ascii_path_element);
  }
  return FilePath(path_ + "/" + ascii_path_element);
}

// static
void PathService::Get(PathKey key, FilePath *out) {
  // Figure out where the source code is for getting test data
  // right from there.
#if defined(_BORINGSSL_PKI_SRCDIR_)
  // We stringify the compile parameter because cmake. sigh.
#define _boringssl_xstr(s) _boringssl_str(s)
#define _boringssl_str(s) #s
  const char pki_srcdir[] = _boringssl_xstr(_BORINGSSL_PKI_SRCDIR_);
  const char pki_curdir[] = "./pki";
  const char curdir[] = ".";
#else
#error "No _BORINGSSL_PKI_SRCDIR"
#endif  // defined(BORINGSSL_PKI_SRCDIR
  // We want to know where the top of pki is to find testdata.  Some things like
  // to run tests in random places with the data files copied around. Let's be
  // flexible, maybe we can't see the source directory...
  if (path_exists(pki_srcdir)) {
    // Try the source code directory
    *out = FilePath(pki_srcdir);
  } else if (path_exists(pki_curdir)) {
    // Try "pki" in the current directory
    *out = FilePath(pki_curdir);
  } else {
    // As a last resort, try just "." and hope for the best, maybe they stripped
    // pki and copied just the data directory.
    *out = FilePath(curdir);
  }
}

}  // namespace fillins

}  // namespace bssl
