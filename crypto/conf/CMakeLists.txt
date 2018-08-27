include_directories(../../include)

add_library(
  conf

  OBJECT

  conf.c
)

add_dependencies(conf global_target)
