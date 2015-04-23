include_directories(. .. ../../include)

if (${ARCH} STREQUAL "x86_64")
  set(
    EC_ARCH_SOURCES

    ecp_nistz256-x86_64.${ASM_EXT}
  )
endif()

if (${ARCH} STREQUAL "x86")
  set(
    EC_ARCH_SOURCES

    ecp_nistz256-x86.${ASM_EXT}
  )
endif()

if (${ARCH} STREQUAL "arm")
  set(
    EC_ARCH_SOURCES

    ecp_nistz256-armv4.${ASM_EXT}
  )
endif()

if (${ARCH} STREQUAL "aarch64")
  set(
    EC_ARCH_SOURCES

    ecp_nistz256-armv8.${ASM_EXT}
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
  simple.c
  wnaf.c

  ${EC_ARCH_SOURCES}
)

# TODO: asm files depend on ecp_nistz256_table.c.

add_executable(
  example_mul

  example_mul.c
)

add_executable(
  ec_test

  ec_test.c
)

target_link_libraries(example_mul crypto)
target_link_libraries(ec_test crypto)

perlasm(ecp_nistz256-x86_64.${ASM_EXT} asm/ecp_nistz256-x86_64.pl)
perlasm(ecp_nistz256-x86.${ASM_EXT} asm/ecp_nistz256-x86.pl)
perlasm(ecp_nistz256-armv4.${ASM_EXT} asm/ecp_nistz256-armv4.pl)
perlasm(ecp_nistz256-armv8.${ASM_EXT} asm/ecp_nistz256-armv8..pl)
