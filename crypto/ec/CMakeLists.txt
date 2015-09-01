include_directories(../../include)

if (${ARCH} STREQUAL "x86_64")
  set(
    EC_ARCH_SOURCES

    ecp_nistz256-x86_64.${ASM_EXT}
  )
endif()

add_library(
  ec

  OBJECT

  ec.c
  ec_asn1.c
  ec_key.c
  ec_montgomery.c
  ecp_nistz256.c
  oct.c
  p224-64.c
  p256-64.c
  util-64.c
  simple.c
  wnaf.c

  ${EC_ARCH_SOURCES}
)

perlasm(ecp_nistz256-x86_64.${ASM_EXT} asm/ecp_nistz256-x86_64.pl)

add_executable(
  example_mul

  example_mul.c

  $<TARGET_OBJECTS:test_support>
)

add_executable(
  ec_test

  ec_test.cc

  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(example_mul crypto)
target_link_libraries(ec_test crypto)
