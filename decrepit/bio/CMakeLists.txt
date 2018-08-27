include_directories(../../include)

add_library(
  bio_decrepit

  OBJECT

  base64_bio.c
)

add_dependencies(bio_decrepit global_target)
