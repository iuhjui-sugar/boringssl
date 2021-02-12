/*
 * Copyright 2021, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "modulewrapper.h"

#include <errno.h>
#include <stdio.h>
#include <string>
#include <unistd.h>

#include <openssl/span.h>

int main() {
  for (;;) {
    auto args = Args::ParseFromFd(STDIN_FILENO);

    AcvpTool tool;

    Span<const uint8_t> algorithm = args->algorithm();
    bool found = false;
    for (const auto &func : kFunctions) {
      if (algorithm.size() == strlen(func.name) &&
          memcmp(algorithm.data(), func.name, algorithm.size()) == 0) {
        if (args->count() != func.expected_args) {
          fprintf(stderr,
                  "\'%s\' operation received %zu arguments but expected %u.\n",
                  func.name, args->count() - 1, func.expected_args);
          return 2;
        }

        if (!func.handler(tool, &(*args)[0])) {
          fprintf(stderr, "\'%s\' operation failed.\n", func.name);
          return 4;
        }

        found = true;
        break;
      }
    }

    if (!found) {
      const std::string name(reinterpret_cast<const char *>(algorithm.data()),
                             algorithm.size());
      fprintf(stderr, "Unknown operation: %s\n", name.c_str());
      return 3;
    }
  }
}
