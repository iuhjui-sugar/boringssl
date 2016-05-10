include_directories(../include)

add_library(
  ssl

  old/s3_both.c
  old/s3_clnt.c
  old/s3_enc.c
  old/s3_lib.c
  old/s3_meth.c
  old/s3_pkt.c
  old/s3_srvr.c
  ssl_lib.c
  old/t1_enc.c
  old/t1_lib.c

  ../ssl/custom_extensions.c
  ../ssl/tls_record.c
  ../ssl/ssl_aead_ctx.c
  ../ssl/ssl_asn1.c
  ../ssl/ssl_buffer.c
  ../ssl/ssl_cert.c
  ../ssl/ssl_cipher.c
  ../ssl/ssl_ecdh.c
  ../ssl/ssl_file.c
  ../ssl/ssl_rsa.c
  ../ssl/ssl_session.c
  ../ssl/ssl_stat.c
)

target_link_libraries(ssl crypto)

add_executable(
  ssl_test

  ssl_test.cc

  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(ssl_test ssl crypto)
add_dependencies(all_tests ssl_test)
