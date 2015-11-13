include_directories(../../include)

add_library(
  curve25519

  OBJECT

  curve25519.c
)

add_executable(
  curve25519_test

  curve25519_test.cc
  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(curve25519_test crypto)
