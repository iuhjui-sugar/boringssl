include_directories(../../include)

add_library(
  hkdf

  OBJECT

  hkdf.c
)

add_dependencies(hkdf global_target)
