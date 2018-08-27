include_directories(../../include)

add_library(
  ecdh_extra

  OBJECT

  ecdh_extra.c
)

add_dependencies(ecdh_extra global_target)
