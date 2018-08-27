include_directories(../../include)

add_library(
  ripemd_decrepit

  OBJECT

  ripemd.c
)

add_dependencies(ripemd_decrepit global_target)
