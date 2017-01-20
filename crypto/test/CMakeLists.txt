add_library(
  test_support

  OBJECT

  file_test.cc
  malloc.cc
  test_util.cc
)

add_library(
  gtest_main
  gtest_main.cc
)
target_link_libraries(gtest_main crypto gtest)
