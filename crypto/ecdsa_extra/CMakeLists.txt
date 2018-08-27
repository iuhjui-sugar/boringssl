include_directories(../../include)

add_library(
  ecdsa_extra

  OBJECT

  ecdsa_asn1.c
)

add_dependencies(ecdsa_extra global_target)
