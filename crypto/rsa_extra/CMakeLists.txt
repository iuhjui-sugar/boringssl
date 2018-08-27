include_directories(../../include)

add_library(
  rsa_extra

  OBJECT

  rsa_asn1.c
  rsa_print.c
)

add_dependencies(rsa_extra global_target)
