include_directories(../../include)

add_library(
  obj_decrepit

  OBJECT

  obj_decrepit.c
)

add_dependencies(obj_decrepit global_target)
