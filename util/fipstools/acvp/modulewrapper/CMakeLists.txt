include_directories(../../../../include)

if(FIPS)
  add_executable(
    modulewrapper

    main.cc
    modulewrapper.cc
  )

  target_compile_options(modulewrapper PRIVATE "-std=c++17")

  add_dependencies(modulewrapper global_target)

  target_link_libraries(modulewrapper crypto)
endif()
