include_directories(../../include)

add_library(
  rsa_decrepit

  OBJECT

  rsa_decrepit.c
)

add_dependencies(rsa_decrepit global_target)
