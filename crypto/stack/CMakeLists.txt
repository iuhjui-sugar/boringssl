include_directories(../../include)

add_library(
  stack

  OBJECT

  stack.c
)

add_dependencies(stack global_target)
