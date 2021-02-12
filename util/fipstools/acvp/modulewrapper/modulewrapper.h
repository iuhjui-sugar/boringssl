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

#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <vector>

#include <openssl/span.h>

using namespace bssl;

constexpr size_t kMaxArgs = 8;
constexpr size_t kMaxArgLength = (1 << 20);
constexpr size_t kMaxNameLength = 30;

static_assert((kMaxArgs - 1 * kMaxArgLength) + kMaxNameLength > (1 << 30),
              "Argument limits permit excessive messages");

// Encapsulation of the ACVP tool that provides an interface to write a reply.
// The default implementation writes the reply to standard out, but may be
// overridden if needed.
class AcvpTool {
 public:
  // Send a reply back to the acvptool.
  //
  // This function is used by the handler functions to write out results and
  // should be customized by the tool implementation.
  virtual bool WriteReply(std::vector<Span<const uint8_t>> spans);

  virtual ~AcvpTool() = default;
};

// Description of an algorithm with its handler callback
struct Handler {
  const char name[kMaxNameLength + 1];
  uint8_t expected_args;
  bool (*handler)(AcvpTool &tool, const Span<const uint8_t>[]);
};

// Callbacks are defined in modulewrapper.cc
extern Handler kFunctions[67];

// Parses input from acvptool and stores the the algorithm name and its
// arguments.
class Args {
 private:
  Args() {}

 public:
  // Parse input from acvptool from the given file descriptor
  //
  // Returns a null pointer if the input did not parse correctly.
  static std::unique_ptr<Args> ParseFromFd(int fd);

  // Name of the algorithm to test (passed as the first argument)
  Span<const uint8_t> algorithm() const {
    return args_[0];
  }

  // Number of arguments (not including algorithm name)
  size_t count() const {
    return num_args_ - 1;
  }

  // Access an argument (not including the algorithm name)
  const Span<const uint8_t>& operator[](size_t idx) const {
    assert(idx <= kMaxArgs - 1);
    return args_[idx + 1];
  }

  // Total length of arguments (not including algorithm name)
  size_t TotalArgLength() const;

 private:
  // Raw buffer of input, starting 16 bytes into the input
  std::vector<uint8_t> buf_;

  // Raw arguments, including algo name as the first argument
  Span<const uint8_t> args_[kMaxArgs];

  // Number of initialized elements in args_ (includes algo name)
  size_t num_args_;
};
