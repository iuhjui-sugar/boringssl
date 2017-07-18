#include <stdio.h>
#include <vector>

#include <gtest/gtest.h>

#include <openssl/ssl.h>

namespace bssl {
namespace {

using IntVec = std::vector<int>;
using IntSpan = Span<int>;
using ConstIntSpan = Span<const int>;

static void TestCtor(IntSpan s, const int *ptr, size_t size) {
  EXPECT_EQ(s.data(), ptr);
  EXPECT_EQ(s.size(), size);
}

static void TestConstCtor(ConstIntSpan s, const int *ptr, size_t size) {
  EXPECT_EQ(s.data(), ptr);
  EXPECT_EQ(s.size(), size);
}

TEST(SpanTest, CtorEmpty) {
  IntSpan s;
  TestCtor(s, nullptr, 0);
}

TEST(SpanTest, CtorFromPtrAndSize) {
  IntVec v = {7, 8, 9, 10};
  IntSpan s(v.data(), v.size());
  TestCtor(s, v.data(), v.size());
}

TEST(SpanTest, CtorFromVector) {
  IntVec v = {1, 2};
  // Const ctor is implicit.
  TestConstCtor(v, v.data(), v.size());
  // Mutable is explicit.
  IntSpan s(v);
  TestCtor(s, v.data(), v.size());
}

TEST(SpanTest, CtorConstFromArray) {
  int v[2] = {10, 11};
  // Array ctor is implicit for const and mutable T.
  TestConstCtor(v, v, sizeof(v));
  TestCtor(v, v, sizeof(v));
}

TEST(SpanTest, MakeSpan) {
  IntVec v = {100, 200, 300};
  TestCtor(MakeSpan(v), v.data(), v.size());
  TestCtor(MakeSpan(v.data(), v.size()), v.data(), v.size());
  TestConstCtor(MakeSpan(v.data(), v.size()), v.data(), v.size());
  TestConstCtor(MakeSpan(v), v.data(), v.size());
}

TEST(SpanTest, MakeConstSpan) {
  IntVec v = {100, 200, 300};
  TestConstCtor(MakeConstSpan(v), v.data(), v.size());
  TestConstCtor(MakeConstSpan(v.data(), v.size()), v.data(), v.size());
  // But not:
  // TestConstCtor(MakeSpan(v), v.data(), v.size());
}

TEST(SpanTest, Accessor) {
  IntVec v({42, 23, 5, 101, 80});
  IntSpan s(v);
  for (size_t i = 0; i < s.size(); ++i) {
    EXPECT_EQ(s[i], v[i]);
    EXPECT_EQ(s.at(i), v.at(i));
  }
  EXPECT_EQ(s.begin(), v.data());
  EXPECT_EQ(s.end(), v.data() + v.size());
}

}  // namespace
}  // namespace bssl
