include_directories(. .. ../../include)

if (${ARCH} STREQUAL "x86_64")
  set(
    CHACHA_ARCH_SOURCES

    chacha20_avx.${ASM_EXT}
    chacha20_avx2.${ASM_EXT}
  )
endif()

if (${ARCH} STREQUAL "arm")
  set(
    CHACHA_ARCH_SOURCES

    chacha_vec_arm.S
  )
endif()

add_library(
  chacha

  OBJECT

  chacha_generic.c
  chacha_vec.c

  ${CHACHA_ARCH_SOURCES}
)

perlasm(chacha20_avx.${ASM_EXT} asm/chacha20_avx.pl)
perlasm(chacha20_avx2.${ASM_EXT} asm/chacha20_avx2.pl)
