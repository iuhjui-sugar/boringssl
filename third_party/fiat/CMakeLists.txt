include_directories(../../include)

add_library(
  fiat

  OBJECT

  curve25519.c
)

add_dependencies(fiat global_target)
