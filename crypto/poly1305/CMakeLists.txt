include_directories(. .. ../../include)

if (${ARCH} STREQUAL "x86_64")
  set(
    POLY1305_ARCH_SOURCES

    poly1305_avx.${ASM_EXT}
    poly1305_avx2.${ASM_EXT}
  )
endif()

if (${ARCH} STREQUAL "arm")
  set(
    POLY1305_ARCH_SOURCES

    poly1305_arm_asm.S
  )
endif()

add_library(
  poly1305

  OBJECT

  poly1305.c
  poly1305_arm.c
  poly1305_vec.c

  ${POLY1305_ARCH_SOURCES}
)

perlasm(poly1305_avx.${ASM_EXT} asm/poly1305_avx.pl)
perlasm(poly1305_avx2.${ASM_EXT} asm/poly1305_avx2.pl)
