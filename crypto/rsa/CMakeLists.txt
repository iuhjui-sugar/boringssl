include_directories(../../include)

add_library(
  rsa

  OBJECT

  blinding.c
  padding.c
  rsa.c
  rsa_asn1.c
  rsa_impl.c
  rsa_pss_asn1.c
)

add_executable(
  rsa_test

  rsa_test.cc

  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(rsa_test crypto)
add_dependencies(all_tests rsa_test)