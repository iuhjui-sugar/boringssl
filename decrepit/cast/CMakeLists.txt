include_directories(../../include)

add_library(
  cast

  OBJECT

  cast.c
  cast_tables.c
)

add_dependencies(cast global_target)
