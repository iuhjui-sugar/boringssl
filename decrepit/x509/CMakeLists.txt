include_directories(../../include)

add_library(
  x509_decrepit

  OBJECT

  x509_decrepit.c
)

add_dependencies(x509_decrepit global_target)
