include_directories(../../include)

add_library(
  bn_extra

  OBJECT

  bn_asn1.c
  convert.c
)

add_dependencies(bn_extra global_target)
