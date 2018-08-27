include_directories(../../include)

add_library(
  rc4_decrepit

  OBJECT

  rc4_decrepit.c
)

add_dependencies(rc4_decrepit global_target)
