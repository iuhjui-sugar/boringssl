include_directories(../../include)

add_library(
  pkcs7

  OBJECT

  pkcs7.c
  pkcs7_x509.c
)

add_dependencies(pkcs7 global_target)
