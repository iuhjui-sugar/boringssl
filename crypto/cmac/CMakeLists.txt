include_directories(../../include)

add_library(
  cmac

  OBJECT

  cmac.c
)

add_dependencies(cmac global_target)
