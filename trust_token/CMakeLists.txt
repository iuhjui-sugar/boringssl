include_directories(../include)

add_library(
  trust_token

  voprf.cc
  privacy_pass.cc
  clear.cc
  trust_token.cc
)

add_dependencies(trust_token global_target)

target_link_libraries(trust_token crypto)

add_executable(
  trust_token_test

  trust_token_test.cc

  $<TARGET_OBJECTS:boringssl_gtest_main>
)

add_dependencies(trust_token_test global_target)

target_link_libraries(trust_token_test test_support_lib boringssl_gtest trust_token crypto)
add_dependencies(all_tests ssl_test)
