include_directories(. .. ../../include)

add_library(
  ecdh

  OBJECT

  ecdh.c
)

add_executable(
  ecdh_test

  ecdh_test.cc
)

target_link_libraries(ecdh_test crypto)
