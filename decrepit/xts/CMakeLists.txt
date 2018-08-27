include_directories(../../include)

add_library(
  xts

  OBJECT

  xts.c
)

add_dependencies(xts global_target)
