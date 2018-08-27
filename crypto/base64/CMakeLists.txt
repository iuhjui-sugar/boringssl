include_directories(../../include)

add_library(
  base64

  OBJECT

  base64.c
)

add_dependencies(base64 global_target)
