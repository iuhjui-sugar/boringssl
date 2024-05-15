/* Copyright (c) 2024, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#if !defined(BORINGSSL_CUSTOM_GET_TEST_DATA)

#include "test_data.h"

#include <stdio.h>
#include <stdlib.h>

#include "file_util.h"

#if defined(OPENSSL_LINUX)
#include <unistd.h>
#endif

#if defined(OPENSSL_APPLE)
#include <mach-o/dyld.h>
#endif

#if defined(OPENSSL_WINDOWS)
#include <windows.h>
#endif

#if defined(BORINGSSL_USE_BAZEL_RUNFILES)
#include "tools/cpp/runfiles/runfiles.h"

using bazel::tools::cpp::runfiles::Runfiles;
#endif


static std::string ReadFileOrExit(const char *path) {
  bssl::ScopedFILE file(fopen(path, "rb"));
  if (file == nullptr) {
    fprintf(stderr, "Could not open '%s'.\n", path);
    abort();
  }

  std::string ret;
  for (;;) {
    char buf[512];
    size_t n = fread(buf, 1, sizeof(buf), file.get());
    if (n == 0) {
      if (feof(file.get())) {
        return ret;
      }
      fprintf(stderr, "Error reading from '%s'.\n", path);
      abort();
    }
    ret.append(buf, n);
  }
}

#if defined(BORINGSSL_USE_BAZEL_RUNFILES)

std::string GetTestData(const char *path) {
  std::string error;
  std::unique_ptr<Runfiles> runfiles(Runfiles::CreateForTest(&error));
  if (runfiles == nullptr) {
    fprintf(stderr, "Could not initialize runfiles: %s\n", error.c_str());
    abort();
  }

  std::string full_path = runfiles->Rlocation(std::string("boringssl/") + path);
  if (full_path.empty()) {
    fprintf(stderr, "Could not find runfile '%s'.\n", path);
    abort();
  }

  return ReadFileOrExit(full_path.c_str());
}

#else  // !BORINGSSL_USE_BAZEL_RUNFILES

static std::string GetExecutablePath() {
#if defined(OPENSSL_LINUX)
  char buf[4096];
  ssize_t ret = readlink("/proc/self/exe", buf, sizeof(buf));
  if (ret < 0) {
    perror("readlink");
    abort();
  }
  if (ret == sizeof(buf)) {
    // readlink silently truncates if the buffer is too small. Just abort and
    // we'll increase this if we ever need to.
    fprintf(stderr, "Buffer was too small for readlink.\n");
    abort();
  }
  return std::string(buf, ret);
#elif defined(OPENSSL_APPLE)
  char buf[4096];
  uint32_t buf_len = sizeof(buf);
  if (_NSGetExecutablePath(buf, &buf_len) != 0) {
    fprintf(stderr, "_NSGetExecutablePath failed.\n");
    abort();
  }
  return buf;
#elif defined(OPENSSL_WINDOWS)
  char buf[4096];
  DWORD ret = GetModuleFileNameA(nullptr, buf, sizeof(buf));
  if (ret == 0 || ret == sizeof(buf)) {
    // GetModuleFileNameA returns the buffer size on truncation.
    fprintf(stderr, "GetModuleFileNameA failed.\n");
    abort();
  }
  return buf;
#else
  fprintf(stderr,
          "BORINGSSL_TEST_DATA_FROM_EXECUTABLE_PATH not supported on this "
          "platform.\n");
  abort();
#endif
}

static void AppendPath(std::string *path, const std::string &component) {
  if (component.empty() || component == ".") {
    return;
  }
  if (!path->empty() && path->back() != '/') {
    path->push_back('/');
  }
  path->append(component);
}

std::string GetTestData(const char *path) {
  const char *root = getenv("BORINGSSL_TEST_DATA_ROOT");
  root = root != nullptr ? root : ".";

  std::string full_path;
  if (getenv("BORINGSSL_TEST_DATA_FROM_EXECUTABLE_PATH") != nullptr) {
    // Remove the last component to get the executable directory.
    full_path = GetExecutablePath();
#if defined(OPENSSL_WINDOWS)
    size_t idx = full_path.find_last_of("/\\");
#else
    size_t idx = full_path.find_last_of('/');
#endif
    if (idx == std::string::npos) {
      fprintf(stderr, "Invalid executable path: %s\n", full_path.c_str());
      abort();
    }
    full_path.resize(idx);

    // It doesn't make sense to request an executable-relative path and then set
    // an absolute root. This check doesn't handle Windows, but it's not
    // necessary for correctness, just catches some misconfigurations.
    if (*root == '/') {
      fprintf(stderr,
              "Unexpected absolute BORINGSSL_TEST_DATA_ROOT used with "
              "BORINGSSL_TEST_DATA_FROM_EXECUTABLE_PATH.\n");
      abort();
    }

    AppendPath(&full_path, root);
  } else {
    full_path = root;
  }

  AppendPath(&full_path, path);
  return ReadFileOrExit(full_path.c_str());
}

#endif  // BORINGSSL_USE_BAZEL_RUNFILES

#endif  // !BORINGSSL_CUSTOM_GET_TEST_DATA
