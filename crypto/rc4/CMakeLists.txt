include_directories(../../include)

add_library(
  rc4

  OBJECT

  rc4.c
)

add_dependencies(rc4 global_target)
