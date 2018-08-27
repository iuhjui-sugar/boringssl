include_directories(../../include)

add_library(
  des_decrepit

  OBJECT

  cfb64ede.c
)

add_dependencies(des_decrepit global_target)
