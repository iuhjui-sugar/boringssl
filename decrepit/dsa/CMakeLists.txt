include_directories(../../include)

add_library(
  dsa_decrepit

  OBJECT

  dsa_decrepit.c
)

add_dependencies(dsa_decrepit global_target)
