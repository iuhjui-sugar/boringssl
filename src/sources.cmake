# This file contains source lists that are also consumed by
# generate_build_files.py.
#
# TODO(davidben): Move the other source lists into this file.

set(
  CRYPTO_TEST_DATA

  crypto/blake2/blake2b256_tests.txt
  crypto/cipher_extra/test/aes_128_cbc_sha1_tls_implicit_iv_tests.txt
  crypto/cipher_extra/test/aes_128_cbc_sha1_tls_tests.txt
  crypto/cipher_extra/test/aes_128_ccm_bluetooth_tests.txt
  crypto/cipher_extra/test/aes_128_ccm_bluetooth_8_tests.txt
  crypto/cipher_extra/test/aes_128_ccm_matter_tests.txt
  crypto/cipher_extra/test/aes_128_ctr_hmac_sha256.txt
  crypto/cipher_extra/test/aes_128_gcm_randnonce_tests.txt
  crypto/cipher_extra/test/aes_128_gcm_siv_tests.txt
  crypto/cipher_extra/test/aes_128_gcm_tests.txt
  crypto/cipher_extra/test/aes_192_gcm_tests.txt
  crypto/cipher_extra/test/aes_256_cbc_sha1_tls_implicit_iv_tests.txt
  crypto/cipher_extra/test/aes_256_cbc_sha1_tls_tests.txt
  crypto/cipher_extra/test/aes_256_ctr_hmac_sha256.txt
  crypto/cipher_extra/test/aes_256_gcm_randnonce_tests.txt
  crypto/cipher_extra/test/aes_256_gcm_siv_tests.txt
  crypto/cipher_extra/test/aes_256_gcm_tests.txt
  crypto/cipher_extra/test/chacha20_poly1305_tests.txt
  crypto/cipher_extra/test/xchacha20_poly1305_tests.txt
  crypto/cipher_extra/test/cipher_tests.txt
  crypto/cipher_extra/test/des_ede3_cbc_sha1_tls_implicit_iv_tests.txt
  crypto/cipher_extra/test/des_ede3_cbc_sha1_tls_tests.txt
  crypto/cipher_extra/test/nist_cavp/aes_128_cbc.txt
  crypto/cipher_extra/test/nist_cavp/aes_128_ctr.txt
  crypto/cipher_extra/test/nist_cavp/aes_128_gcm.txt
  crypto/cipher_extra/test/nist_cavp/aes_192_cbc.txt
  crypto/cipher_extra/test/nist_cavp/aes_192_ctr.txt
  crypto/cipher_extra/test/nist_cavp/aes_256_cbc.txt
  crypto/cipher_extra/test/nist_cavp/aes_256_ctr.txt
  crypto/cipher_extra/test/nist_cavp/aes_256_gcm.txt
  crypto/cipher_extra/test/nist_cavp/tdes_cbc.txt
  crypto/cipher_extra/test/nist_cavp/tdes_ecb.txt
  crypto/curve25519/ed25519_tests.txt
  crypto/ecdh_extra/ecdh_tests.txt
  crypto/evp/evp_tests.txt
  crypto/evp/scrypt_tests.txt
  crypto/fipsmodule/aes/aes_tests.txt
  crypto/fipsmodule/bn/test/exp_tests.txt
  crypto/fipsmodule/bn/test/gcd_tests.txt
  crypto/fipsmodule/bn/test/miller_rabin_tests.txt
  crypto/fipsmodule/bn/test/mod_exp_tests.txt
  crypto/fipsmodule/bn/test/mod_inv_tests.txt
  crypto/fipsmodule/bn/test/mod_mul_tests.txt
  crypto/fipsmodule/bn/test/mod_sqrt_tests.txt
  crypto/fipsmodule/bn/test/product_tests.txt
  crypto/fipsmodule/bn/test/quotient_tests.txt
  crypto/fipsmodule/bn/test/shift_tests.txt
  crypto/fipsmodule/bn/test/sum_tests.txt
  crypto/fipsmodule/cmac/cavp_3des_cmac_tests.txt
  crypto/fipsmodule/cmac/cavp_aes128_cmac_tests.txt
  crypto/fipsmodule/cmac/cavp_aes192_cmac_tests.txt
  crypto/fipsmodule/cmac/cavp_aes256_cmac_tests.txt
  crypto/fipsmodule/ec/ec_scalar_base_mult_tests.txt
  crypto/fipsmodule/ec/p256-nistz_tests.txt
  crypto/fipsmodule/ecdsa/ecdsa_sign_tests.txt
  crypto/fipsmodule/ecdsa/ecdsa_verify_tests.txt
  crypto/fipsmodule/modes/gcm_tests.txt
  crypto/fipsmodule/rand/ctrdrbg_vectors.txt
  crypto/hmac_extra/hmac_tests.txt
  crypto/hpke/hpke_test_vectors.txt
  crypto/kyber/keccak_tests.txt
  crypto/pkcs8/test/empty_password.p12
  crypto/pkcs8/test/no_encryption.p12
  crypto/pkcs8/test/nss.p12
  crypto/pkcs8/test/null_password.p12
  crypto/pkcs8/test/openssl.p12
  crypto/pkcs8/test/pbes2_sha1.p12
  crypto/pkcs8/test/pbes2_sha256.p12
  crypto/pkcs8/test/unicode_password.p12
  crypto/pkcs8/test/windows.p12
  crypto/poly1305/poly1305_tests.txt
  crypto/siphash/siphash_tests.txt
  crypto/x509/test/basic_constraints_ca.pem
  crypto/x509/test/basic_constraints_ca_pathlen_0.pem
  crypto/x509/test/basic_constraints_ca_pathlen_1.pem
  crypto/x509/test/basic_constraints_ca_pathlen_10.pem
  crypto/x509/test/basic_constraints_leaf.pem
  crypto/x509/test/basic_constraints_none.pem
  crypto/x509/test/invalid_extension_intermediate.pem
  crypto/x509/test/invalid_extension_intermediate_authority_key_identifier.pem
  crypto/x509/test/invalid_extension_intermediate_basic_constraints.pem
  crypto/x509/test/invalid_extension_intermediate_ext_key_usage.pem
  crypto/x509/test/invalid_extension_intermediate_key_usage.pem
  crypto/x509/test/invalid_extension_intermediate_name_constraints.pem
  crypto/x509/test/invalid_extension_intermediate_subject_alt_name.pem
  crypto/x509/test/invalid_extension_intermediate_subject_key_identifier.pem
  crypto/x509/test/invalid_extension_leaf.pem
  crypto/x509/test/invalid_extension_leaf_authority_key_identifier.pem
  crypto/x509/test/invalid_extension_leaf_basic_constraints.pem
  crypto/x509/test/invalid_extension_leaf_ext_key_usage.pem
  crypto/x509/test/invalid_extension_leaf_key_usage.pem
  crypto/x509/test/invalid_extension_leaf_name_constraints.pem
  crypto/x509/test/invalid_extension_leaf_subject_alt_name.pem
  crypto/x509/test/invalid_extension_leaf_subject_key_identifier.pem
  crypto/x509/test/invalid_extension_root.pem
  crypto/x509/test/invalid_extension_root_authority_key_identifier.pem
  crypto/x509/test/invalid_extension_root_basic_constraints.pem
  crypto/x509/test/invalid_extension_root_ext_key_usage.pem
  crypto/x509/test/invalid_extension_root_key_usage.pem
  crypto/x509/test/invalid_extension_root_name_constraints.pem
  crypto/x509/test/invalid_extension_root_subject_alt_name.pem
  crypto/x509/test/invalid_extension_root_subject_key_identifier.pem
  crypto/x509/test/many_constraints.pem
  crypto/x509/test/many_names1.pem
  crypto/x509/test/many_names2.pem
  crypto/x509/test/many_names3.pem
  crypto/x509/test/policy_intermediate_any.pem
  crypto/x509/test/policy_intermediate_duplicate.pem
  crypto/x509/test/policy_intermediate_invalid.pem
  crypto/x509/test/policy_intermediate_mapped_any.pem
  crypto/x509/test/policy_intermediate_mapped_oid3.pem
  crypto/x509/test/policy_intermediate_mapped.pem
  crypto/x509/test/policy_intermediate_require_duplicate.pem
  crypto/x509/test/policy_intermediate_require_no_policies.pem
  crypto/x509/test/policy_intermediate_require.pem
  crypto/x509/test/policy_intermediate_require1.pem
  crypto/x509/test/policy_intermediate_require2.pem
  crypto/x509/test/policy_intermediate.pem
  crypto/x509/test/policy_leaf_any.pem
  crypto/x509/test/policy_leaf_duplicate.pem
  crypto/x509/test/policy_leaf_invalid.pem
  crypto/x509/test/policy_leaf_none.pem
  crypto/x509/test/policy_leaf_oid1.pem
  crypto/x509/test/policy_leaf_oid2.pem
  crypto/x509/test/policy_leaf_oid3.pem
  crypto/x509/test/policy_leaf_oid4.pem
  crypto/x509/test/policy_leaf_oid5.pem
  crypto/x509/test/policy_leaf_require.pem
  crypto/x509/test/policy_leaf_require1.pem
  crypto/x509/test/policy_leaf.pem
  crypto/x509/test/policy_root_cross_inhibit_mapping.pem
  crypto/x509/test/policy_root.pem
  crypto/x509/test/policy_root2.pem
  crypto/x509/test/pss_sha1_explicit.pem
  crypto/x509/test/pss_sha1_mgf1_syntax_error.pem
  crypto/x509/test/pss_sha1.pem
  crypto/x509/test/pss_sha224.pem
  crypto/x509/test/pss_sha256_explicit_trailer.pem
  crypto/x509/test/pss_sha256_mgf1_sha384.pem
  crypto/x509/test/pss_sha256_mgf1_syntax_error.pem
  crypto/x509/test/pss_sha256_omit_nulls.pem
  crypto/x509/test/pss_sha256_salt_overflow.pem
  crypto/x509/test/pss_sha256_salt31.pem
  crypto/x509/test/pss_sha256_unknown_mgf.pem
  crypto/x509/test/pss_sha256_wrong_trailer.pem
  crypto/x509/test/pss_sha256.pem
  crypto/x509/test/pss_sha384.pem
  crypto/x509/test/pss_sha512.pem
  crypto/x509/test/some_names1.pem
  crypto/x509/test/some_names2.pem
  crypto/x509/test/some_names3.pem
  crypto/x509/test/trailing_data_leaf_authority_key_identifier.pem
  crypto/x509/test/trailing_data_leaf_basic_constraints.pem
  crypto/x509/test/trailing_data_leaf_ext_key_usage.pem
  crypto/x509/test/trailing_data_leaf_key_usage.pem
  crypto/x509/test/trailing_data_leaf_name_constraints.pem
  crypto/x509/test/trailing_data_leaf_subject_alt_name.pem
  crypto/x509/test/trailing_data_leaf_subject_key_identifier.pem
  third_party/wycheproof_testvectors/aes_cbc_pkcs5_test.txt
  third_party/wycheproof_testvectors/aes_cmac_test.txt
  third_party/wycheproof_testvectors/aes_gcm_siv_test.txt
  third_party/wycheproof_testvectors/aes_gcm_test.txt
  third_party/wycheproof_testvectors/chacha20_poly1305_test.txt
  third_party/wycheproof_testvectors/dsa_test.txt
  third_party/wycheproof_testvectors/ecdh_secp224r1_test.txt
  third_party/wycheproof_testvectors/ecdh_secp256r1_test.txt
  third_party/wycheproof_testvectors/ecdh_secp384r1_test.txt
  third_party/wycheproof_testvectors/ecdh_secp521r1_test.txt
  third_party/wycheproof_testvectors/ecdsa_secp224r1_sha224_test.txt
  third_party/wycheproof_testvectors/ecdsa_secp224r1_sha256_test.txt
  third_party/wycheproof_testvectors/ecdsa_secp224r1_sha512_test.txt
  third_party/wycheproof_testvectors/ecdsa_secp256r1_sha256_test.txt
  third_party/wycheproof_testvectors/ecdsa_secp256r1_sha512_test.txt
  third_party/wycheproof_testvectors/ecdsa_secp384r1_sha384_test.txt
  third_party/wycheproof_testvectors/ecdsa_secp384r1_sha512_test.txt
  third_party/wycheproof_testvectors/ecdsa_secp521r1_sha512_test.txt
  third_party/wycheproof_testvectors/eddsa_test.txt
  third_party/wycheproof_testvectors/hkdf_sha1_test.txt
  third_party/wycheproof_testvectors/hkdf_sha256_test.txt
  third_party/wycheproof_testvectors/hkdf_sha384_test.txt
  third_party/wycheproof_testvectors/hkdf_sha512_test.txt
  third_party/wycheproof_testvectors/hmac_sha1_test.txt
  third_party/wycheproof_testvectors/hmac_sha224_test.txt
  third_party/wycheproof_testvectors/hmac_sha256_test.txt
  third_party/wycheproof_testvectors/hmac_sha384_test.txt
  third_party/wycheproof_testvectors/hmac_sha512_test.txt
  third_party/wycheproof_testvectors/kwp_test.txt
  third_party/wycheproof_testvectors/kw_test.txt
  third_party/wycheproof_testvectors/primality_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_2048_sha1_mgf1sha1_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_2048_sha224_mgf1sha1_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_2048_sha224_mgf1sha224_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_2048_sha256_mgf1sha1_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_2048_sha256_mgf1sha256_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_2048_sha384_mgf1sha1_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_2048_sha384_mgf1sha384_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_2048_sha512_mgf1sha1_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_2048_sha512_mgf1sha512_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_3072_sha256_mgf1sha1_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_3072_sha256_mgf1sha256_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_3072_sha512_mgf1sha1_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_3072_sha512_mgf1sha512_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_4096_sha256_mgf1sha1_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_4096_sha256_mgf1sha256_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_4096_sha512_mgf1sha1_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_4096_sha512_mgf1sha512_test.txt
  third_party/wycheproof_testvectors/rsa_oaep_misc_test.txt
  third_party/wycheproof_testvectors/rsa_pkcs1_2048_test.txt
  third_party/wycheproof_testvectors/rsa_pkcs1_3072_test.txt
  third_party/wycheproof_testvectors/rsa_pkcs1_4096_test.txt
  third_party/wycheproof_testvectors/rsa_pss_2048_sha1_mgf1_20_test.txt
  third_party/wycheproof_testvectors/rsa_pss_2048_sha256_mgf1_0_test.txt
  third_party/wycheproof_testvectors/rsa_pss_2048_sha256_mgf1_32_test.txt
  third_party/wycheproof_testvectors/rsa_pss_3072_sha256_mgf1_32_test.txt
  third_party/wycheproof_testvectors/rsa_pss_4096_sha256_mgf1_32_test.txt
  third_party/wycheproof_testvectors/rsa_pss_4096_sha512_mgf1_32_test.txt
  third_party/wycheproof_testvectors/rsa_pss_misc_test.txt
  third_party/wycheproof_testvectors/rsa_sig_gen_misc_test.txt
  third_party/wycheproof_testvectors/rsa_signature_2048_sha224_test.txt
  third_party/wycheproof_testvectors/rsa_signature_2048_sha256_test.txt
  third_party/wycheproof_testvectors/rsa_signature_2048_sha384_test.txt
  third_party/wycheproof_testvectors/rsa_signature_2048_sha512_test.txt
  third_party/wycheproof_testvectors/rsa_signature_3072_sha256_test.txt
  third_party/wycheproof_testvectors/rsa_signature_3072_sha384_test.txt
  third_party/wycheproof_testvectors/rsa_signature_3072_sha512_test.txt
  third_party/wycheproof_testvectors/rsa_signature_4096_sha384_test.txt
  third_party/wycheproof_testvectors/rsa_signature_4096_sha512_test.txt
  third_party/wycheproof_testvectors/rsa_signature_test.txt
  third_party/wycheproof_testvectors/x25519_test.txt
  third_party/wycheproof_testvectors/xchacha20_poly1305_test.txt
)
