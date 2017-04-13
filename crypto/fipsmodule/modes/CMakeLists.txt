include_directories(../../include)

if (${ARCH} STREQUAL "x86_64")
  set(
    MODES_ARCH_SOURCES

  )
endif()

if (${ARCH} STREQUAL "x86")
  set(
    MODES_ARCH_SOURCES

  )
endif()

if (${ARCH} STREQUAL "arm")
  set(
    MODES_ARCH_SOURCES

  )
endif()

if (${ARCH} STREQUAL "aarch64")
  set(
    MODES_ARCH_SOURCES

  )
endif()

if (${ARCH} STREQUAL "ppc64le")
  set(
    MODES_ARCH_SOURCES

  )
endif()

add_library(
  modes

  OBJECT

  cbc.c
  cfb.c
  ctr.c
  gcm.c
  ofb.c
  polyval.c

  ${MODES_ARCH_SOURCES}
)


add_executable(
  gcm_test

  gcm_test.cc

  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(gcm_test crypto)
add_dependencies(all_tests gcm_test)
