include_directories(../../include)

if (((${ARCH} STREQUAL "x86_64") OR (${ARCH} STREQUAL "x86")) AND
    (CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang"))
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mrdrnd")
endif()

add_library(
  rand

  OBJECT

  deterministic.c
  rand.c
  urandom.c
  windows.c

  ${RAND_ARCH_SOURCES}
)
