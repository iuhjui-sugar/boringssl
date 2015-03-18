include_directories(. .. ../include)

add_subdirectory(pqueue)

add_library(
  ssl

  d1_both.c
  d1_clnt.c
  d1_lib.c
  d1_meth.c
  d1_pkt.c
  d1_srtp.c
  d1_srvr.c
  s3_both.c
  s3_clnt.c
  s3_enc.c
  s3_lib.c
  s3_meth.c
  s3_pkt.c
  s3_srvr.c
  ssl_algs.c
  ssl_asn1.c
  ssl_cert.c
  ssl_ciph.c
  ssl_lib.c
  ssl_rsa.c
  ssl_sess.c
  ssl_stat.c
  ssl_txt.c
  t1_enc.c
  t1_lib.c
  t1_reneg.c

  $<TARGET_OBJECTS:pqueue>
)

file(GLOB HDRS ../include/openssl/*.h)

set(PKG_CONFIG_PREFIX "${CMAKE_INSTALL_PREFIX}")
configure_file(
  libssl.pc.in
  libssl.pc
  @ONLY
)

set(PKG_CONFIG_PREFIX "${CMAKE_INSTALL_PREFIX}")
configure_file(
  openssl.pc.in
  openssl.pc
  @ONLY
)

set_target_properties(
  ssl

  PROPERTIES
  PUBLIC_HEADER "${HDRS}"
)

install(
  TARGETS ssl
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  PUBLIC_HEADER DESTINATION include/openssl
)

set(PC_FILES)
list(APPEND PC_FILES
  ${CMAKE_CURRENT_BINARY_DIR}/libssl.pc
  ${CMAKE_CURRENT_BINARY_DIR}/openssl.pc
)

install(
  FILES ${PC_FILES} DESTINATION lib/pkgconfig/
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_WRITE GROUP_READ WORLD_READ
)

add_executable(
  ssl_test

  ssl_test.c
)

target_link_libraries(ssl_test ssl crypto)
