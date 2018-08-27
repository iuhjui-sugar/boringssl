include_directories(../../include)

add_library(
  blowfish

  OBJECT

  blowfish.c
)

add_dependencies(blowfish global_target)
