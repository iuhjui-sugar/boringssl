include_directories(../../include)

add_library(
  cfb

  OBJECT

  cfb.c
)

add_dependencies(cfb global_target)
