include_directories(../../include)

if (${ARCH} STREQUAL "x86_64")
  set(
    SHA256x16_ARCH_SOURCES

    asm/sha256x16_x86_64.S
  )
endif()

add_library(
  sha256x16

  OBJECT

  sha256x16.c

  ${SHA256x16_ARCH_SOURCES}
)
