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

set(HDRS)
list(APPEND HDRS
  ../include/openssl/aead.h
  ../include/openssl/aes.h
  ../include/openssl/asn1.h
  ../include/openssl/asn1_mac.h
  ../include/openssl/asn1t.h
  ../include/openssl/base64.h
  ../include/openssl/base.h
  ../include/openssl/bio.h
  ../include/openssl/bn.h
  ../include/openssl/buf.h
  ../include/openssl/bytestring.h
  ../include/openssl/chacha.h
  ../include/openssl/cipher.h
  ../include/openssl/conf.h
  ../include/openssl/cpu.h
  ../include/openssl/crypto.h
  ../include/openssl/des.h
  ../include/openssl/dh.h
  ../include/openssl/digest.h
  ../include/openssl/dsa.h
  ../include/openssl/dtls1.h
  ../include/openssl/ecdh.h
  ../include/openssl/ecdsa.h
  ../include/openssl/ec.h
  ../include/openssl/ec_key.h
  ../include/openssl/engine.h
  ../include/openssl/err.h
  ../include/openssl/evp.h
  ../include/openssl/ex_data.h
  ../include/openssl/hkdf.h
  ../include/openssl/hmac.h
  ../include/openssl/lhash.h
  ../include/openssl/lhash_macros.h
  ../include/openssl/md4.h
  ../include/openssl/md5.h
  ../include/openssl/mem.h
  ../include/openssl/modes.h
  ../include/openssl/objects.h
  ../include/openssl/obj.h
  ../include/openssl/obj_mac.h
  ../include/openssl/opensslfeatures.h
  ../include/openssl/opensslv.h
  ../include/openssl/ossl_typ.h
  ../include/openssl/pem.h
  ../include/openssl/pkcs12.h
  ../include/openssl/pkcs7.h
  ../include/openssl/pkcs8.h
  ../include/openssl/poly1305.h
  ../include/openssl/pqueue.h
  ../include/openssl/rand.h
  ../include/openssl/rc4.h
  ../include/openssl/rsa.h
  ../include/openssl/safestack.h
  ../include/openssl/sha.h
  ../include/openssl/srtp.h
  ../include/openssl/ssl23.h
  ../include/openssl/ssl2.h
  ../include/openssl/ssl3.h
  ../include/openssl/ssl.h
  ../include/openssl/stack.h
  ../include/openssl/stack_macros.h
  ../include/openssl/thread.h
  ../include/openssl/time_support.h
  ../include/openssl/tls1.h
  ../include/openssl/type_check.h
  ../include/openssl/x509.h
  ../include/openssl/x509v3.h
  ../include/openssl/x509_vfy.h
)

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
