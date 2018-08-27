include_directories(../../include)

add_library(
  obj

  OBJECT

  obj.c
  obj_xref.c
)

add_dependencies(obj global_target)
