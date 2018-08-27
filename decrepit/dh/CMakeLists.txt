include_directories(../../include)

add_library(
  dh_decrepit

  OBJECT

  dh_decrepit.c
)

add_dependencies(dh_decrepit global_target)
