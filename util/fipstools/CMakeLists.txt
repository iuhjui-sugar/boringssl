if(NOT MSVC)
  add_executable(
    test_fips

    test_fips.c
  )
  target_link_libraries(test_fips crypto)
endif()
