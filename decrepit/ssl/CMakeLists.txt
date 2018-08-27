include_directories(../../include)

add_library(
  ssl_decrepit

  OBJECT

  ssl_decrepit.c
)

add_dependencies(ssl_decrepit global_target)
