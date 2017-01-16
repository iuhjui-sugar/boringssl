include_directories(../../include)

if (${ARCH} STREQUAL "arm")
  set(
    CHACHA20_POLY1305_ARCH_SOURCES

    poly1305_arm_asm.S
    chacha-armv4.${ASM_EXT}
  )
endif()

if (${ARCH} STREQUAL "aarch64")
  set(
    CHACHA20_POLY1305_ARCH_SOURCES

    chacha-armv8.${ASM_EXT}
  )
endif()

if (${ARCH} STREQUAL "x86")
  set(
    CHACHA20_POLY1305_ARCH_SOURCES

    chacha-x86.${ASM_EXT}
  )
endif()

if (${ARCH} STREQUAL "x86_64")
  set(
    CHACHA20_POLY1305_ARCH_SOURCES

    poly1305_x86_64.${ASM_EXT}
    chacha-x86_64.${ASM_EXT}
    chacha20_poly1305_x86_64.${ASM_EXT}
  )
endif()

add_library(
  chacha20poly1305

  OBJECT

  poly1305.c
  poly1305_arm.c
  poly1305_vec.c
  poly1305_x86.c
  chacha.c

  ${CHACHA20_POLY1305_ARCH_SOURCES}
)

add_executable(
  poly1305_test

  poly1305_test.cc
  $<TARGET_OBJECTS:test_support>
)

add_executable(
  chacha_test

  chacha_test.cc
  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(poly1305_test crypto)
add_dependencies(all_tests poly1305_test)
target_link_libraries(chacha_test crypto)
add_dependencies(all_tests chacha_test)

perlasm(chacha-armv4.${ASM_EXT} asm/chacha-armv4.pl)
perlasm(chacha-armv8.${ASM_EXT} asm/chacha-armv8.pl)
perlasm(chacha-x86.${ASM_EXT} asm/chacha-x86.pl)
perlasm(chacha-x86_64.${ASM_EXT} asm/chacha-x86_64.pl)
perlasm(poly1305_x86_64.${ASM_EXT} asm/poly1305_x86_64.pl)
perlasm(chacha20_poly1305_x86_64.${ASM_EXT} asm/chacha20_poly1305_x86_64.pl)
