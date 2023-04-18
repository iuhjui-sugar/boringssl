project(pki)
cmake_minimum_required(VERSION 3.25)
set(CMAKE_CXX_STANDARD 17)

add_library(
  pki

  fillins/time.cc
  fillins/ip_address.cc
  fillins/utf_string_conversions.cc
  fillins/string_util.cc
  fillins/base64.cc
  string_util.cc
  trust_store.cc
  trust_store_collection.cc
  parse_certificate.cc
  parsed_certificate.cc
  parser.cc
  parse_values.cc
  parse_name.cc
  parsed_certificate.cc
  name_constraints.cc
  input.cc
  tag.cc
  cert_errors.cc
  general_names.cc
  pem.cc
  crl.cc
  revocation_util.cc
  encode_values.cc
  verify_name_match.cc
  cert_errors.cc
  common_cert_errors.cc
  parse_certificate.cc
  parsed_certificate.cc
  extended_key_usage.cc
  certificate_policies.cc
  verify_certificate_chain.cc
  verify_signed_data.cc
  signature_algorithm.cc
  cert_error_id.cc
  cert_error_params.cc
  mock_signature_verify_cache.cc
  trust_store.cc
  trust_store_collection.cc
  trust_store_in_memory.cc
  simple_path_builder_delegate.cc
  cert_issuer_source_static.cc
  path_builder.cc
)
# Although libssl also provides headers that require an include directory, the
# flag is already specified by libcrypto, so we omit target_include_directories
# here.
install_if_enabled(TARGETS pki EXPORT OpenSSLTargets ${INSTALL_DESTINATION_DEFAULT})
set_property(TARGET pki PROPERTY EXPORT_NAME PKI)
set_property(TARGET pki PROPERTY CXX_STANDARD 17)
target_link_libraries(pki ssl crypto)

add_executable(
  pki_test

  fillins/path_service.cc
  fillins/file_util.cc
  fillins/openssl_util.cc
  test_helpers.cc
  string_util_unittest.cc
  parser_unittest.cc
  parse_values_unittest.cc
  input_unittest.cc
  signature_algorithm_unittest.cc
  extended_key_usage_unittest.cc
  parse_name_unittest.cc
  verify_name_match_unittest.cc
  verify_signed_data_unittest.cc
  parse_certificate_unittest.cc
  parsed_certificate_unittest.cc
  simple_path_builder_delegate_unittest.cc
  trust_store_collection_unittest.cc
  certificate_policies_unittest.cc
  verify_certificate_chain_unittest.cc
  nist_pkits_unittest.cc
  path_builder_pkits_unittest.cc
  name_constraints_unittest.cc
#  cert_issuer_source_static_unittest.cc
#  ocsp_unittest.cc
#  path_builder_unittest.cc
  path_builder_verify_certificate_chain_unittest.cc
  verify_certificate_chain_pkits_unittest.cc
)
target_link_libraries(pki_test test_support_lib boringssl_gtest_main pki ssl crypto)
set_property(TARGET pki_test PROPERTY CXX_STANDARD 17)
add_dependencies(all_tests pki_test)


