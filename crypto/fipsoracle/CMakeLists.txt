include_directories(../../include)

add_executable(
  cavp_cipher_test

  cavp_cipher_test.cc
  cavp_test_util.h
  cavp_test_util.cc
  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(cavp_cipher_test crypto)
