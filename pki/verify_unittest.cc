/* Copyright (c) 2023, Google Inc.
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

#include <string.h>

#include <optional>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/pki/verify.h>
#include <openssl/sha.h>

#include "test_helpers.h"

namespace verify {

static std::unique_ptr<TrustStore> MozillaRootStore() {
  std::string diagnostic;
  return TrustStore::FromDER(bssl::ReadTestFileToString(
                                 "testdata/verify_test/mozilla_roots.der"),
                             &diagnostic)
      .value();
}

using ::testing::UnorderedElementsAre;

static std::string GetTestdata(std::string_view filename) {
  return bssl::ReadTestFileToString("testdata/verify_test/" +
                                    std::string(filename));
}

TEST(VerifyTest, GoogleChain) {
  const std::string leaf = GetTestdata("google-leaf.der");
  const std::string intermediate1 = GetTestdata("google-intermediate1.der");
  const std::string intermediate2 = GetTestdata("google-intermediate2.der");
  Opts opts;
  opts.leaf_cert = leaf;
  opts.intermediates = {intermediate1, intermediate2};
  opts.time = 1499727444;
  // Set the |max_path_building_depth| explicitly to test the non-default case.
  // Depth of 5 is enough to successfully find a path.
  opts.max_path_building_depth = 5;
  std::unique_ptr<TrustStore> roots = MozillaRootStore();
  opts.trust_store = roots.get();

  Error error;
  ASSERT_TRUE(Verify(opts, &error)) << error.AsString();

  // Depth of 2 is not enough to find a path.
  opts.max_path_building_depth = 2;
  EXPECT_FALSE(Verify(opts, &error));
  EXPECT_STREQ(error.AsString().c_str(),
               "No path was found within the depth limit");
}

}  // namespace verify
