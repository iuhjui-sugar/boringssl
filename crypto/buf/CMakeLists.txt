include_directories(../../include)

add_library(
  buf

  OBJECT

  buf.c
)

add_dependencies(buf global_target)
