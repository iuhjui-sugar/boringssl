add_subdirectory(cast)
add_subdirectory(blowfish)
add_subdirectory(bio)

add_library(
  decrepit

  $<TARGET_OBJECTS:bio_extra>
  $<TARGET_OBJECTS:blowfish>
  $<TARGET_OBJECTS:cast>
)
