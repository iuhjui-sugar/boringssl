include_directories(../../include)

add_library(
  digest_extra

  OBJECT

  digest_extra.c
)

add_dependencies(digest_extra global_target)
