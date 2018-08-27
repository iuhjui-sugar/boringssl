include_directories(../../include)

add_library(
  evp_decrepit

  OBJECT

  dss1.c
  evp_do_all.c
)

add_dependencies(evp_decrepit global_target)
