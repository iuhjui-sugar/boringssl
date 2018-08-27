include_directories(../../include)

add_library(
  engine

  OBJECT

  engine.c
)

add_dependencies(engine global_target)
