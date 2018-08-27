include_directories(../../include)

add_library(
  pool

  OBJECT

  pool.c
)

add_dependencies(pool global_target)
