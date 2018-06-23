include_directories(../../include)

add_executable(
  bssl_shim

  async_bio.cc
  bssl_shim.cc
  handshake.cc
  packeted_bio.cc
  settings_writer.cc
  test_config.cc
  test_state.cc

  $<TARGET_OBJECTS:test_support>
)

add_executable(
  handshaker

  async_bio.cc
  handshake.cc
  handshaker.cc
  packeted_bio.cc
  settings_writer.cc
  test_config.cc
  test_state.cc

  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(bssl_shim ssl crypto)
target_link_libraries(handshaker ssl crypto)
