/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <openssl/err.h>

#include <openssl/ec.h>

const ERR_STRING_DATA EC_error_string_data[] = {
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_GROUP_copy, 0), "EC_GROUP_copy"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_GROUP_get_degree, 0), "EC_GROUP_get_degree"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_GROUP_new_by_curve_name, 0), "EC_GROUP_new_by_curve_name"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_KEY_check_key, 0), "EC_KEY_check_key"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_KEY_copy, 0), "EC_KEY_copy"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_KEY_generate_key, 0), "EC_KEY_generate_key"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_KEY_new_method, 0), "EC_KEY_new_method"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_KEY_set_public_key_affine_coordinates, 0), "EC_KEY_set_public_key_affine_coordinates"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_POINT_add, 0), "EC_POINT_add"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_POINT_cmp, 0), "EC_POINT_cmp"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_POINT_copy, 0), "EC_POINT_copy"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_POINT_dbl, 0), "EC_POINT_dbl"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_POINT_dup, 0), "EC_POINT_dup"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_POINT_get_affine_coordinates_GFp, 0), "EC_POINT_get_affine_coordinates_GFp"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_POINT_invert, 0), "EC_POINT_invert"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_POINT_is_at_infinity, 0), "EC_POINT_is_at_infinity"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_POINT_is_on_curve, 0), "EC_POINT_is_on_curve"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_POINT_make_affine, 0), "EC_POINT_make_affine"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_POINT_new, 0), "EC_POINT_new"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_POINT_oct2point, 0), "EC_POINT_oct2point"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_POINT_point2oct, 0), "EC_POINT_point2oct"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_POINT_set_affine_coordinates_GFp, 0), "EC_POINT_set_affine_coordinates_GFp"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_POINT_set_compressed_coordinates_GFp, 0), "EC_POINT_set_compressed_coordinates_GFp"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_POINT_set_to_infinity, 0), "EC_POINT_set_to_infinity"},
  {ERR_PACK(ERR_LIB_EC, EC_F_EC_POINTs_make_affine, 0), "EC_POINTs_make_affine"},
  {ERR_PACK(ERR_LIB_EC, EC_F_compute_wNAF, 0), "compute_wNAF"},
  {ERR_PACK(ERR_LIB_EC, EC_F_d2i_ECPKParameters, 0), "d2i_ECPKParameters"},
  {ERR_PACK(ERR_LIB_EC, EC_F_d2i_ECParameters, 0), "d2i_ECParameters"},
  {ERR_PACK(ERR_LIB_EC, EC_F_d2i_ECPrivateKey, 0), "d2i_ECPrivateKey"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_GFp_mont_field_decode, 0), "ec_GFp_mont_field_decode"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_GFp_mont_field_encode, 0), "ec_GFp_mont_field_encode"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_GFp_mont_field_mul, 0), "ec_GFp_mont_field_mul"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_GFp_mont_field_set_to_one, 0), "ec_GFp_mont_field_set_to_one"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_GFp_mont_field_sqr, 0), "ec_GFp_mont_field_sqr"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_GFp_mont_group_set_curve, 0), "ec_GFp_mont_group_set_curve"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_GFp_simple_group_check_discriminant, 0), "ec_GFp_simple_group_check_discriminant"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_GFp_simple_group_set_curve, 0), "ec_GFp_simple_group_set_curve"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_GFp_simple_make_affine, 0), "ec_GFp_simple_make_affine"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_GFp_simple_oct2point, 0), "ec_GFp_simple_oct2point"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_GFp_simple_point2oct, 0), "ec_GFp_simple_point2oct"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_GFp_simple_point_get_affine_coordinates, 0), "ec_GFp_simple_point_get_affine_coordinates"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_GFp_simple_point_set_affine_coordinates, 0), "ec_GFp_simple_point_set_affine_coordinates"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_GFp_simple_points_make_affine, 0), "ec_GFp_simple_points_make_affine"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_GFp_simple_set_compressed_coordinates, 0), "ec_GFp_simple_set_compressed_coordinates"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_asn1_group2pkparameters, 0), "ec_asn1_group2pkparameters"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_asn1_pkparameters2group, 0), "ec_asn1_pkparameters2group"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_group_new, 0), "ec_group_new"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_group_new_curve_GFp, 0), "ec_group_new_curve_GFp"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_group_new_from_data, 0), "ec_group_new_from_data"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_point_set_Jprojective_coordinates_GFp, 0), "ec_point_set_Jprojective_coordinates_GFp"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_pre_comp_new, 0), "ec_pre_comp_new"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_wNAF_mul, 0), "ec_wNAF_mul"},
  {ERR_PACK(ERR_LIB_EC, EC_F_ec_wNAF_precompute_mult, 0), "ec_wNAF_precompute_mult"},
  {ERR_PACK(ERR_LIB_EC, EC_F_i2d_ECPKParameters, 0), "i2d_ECPKParameters"},
  {ERR_PACK(ERR_LIB_EC, EC_F_i2d_ECParameters, 0), "i2d_ECParameters"},
  {ERR_PACK(ERR_LIB_EC, EC_F_i2d_ECPrivateKey, 0), "i2d_ECPrivateKey"},
  {ERR_PACK(ERR_LIB_EC, EC_F_i2o_ECPublicKey, 0), "i2o_ECPublicKey"},
  {ERR_PACK(ERR_LIB_EC, EC_F_o2i_ECPublicKey, 0), "o2i_ECPublicKey"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_BUFFER_TOO_SMALL), "BUFFER_TOO_SMALL"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_COORDINATES_OUT_OF_RANGE), "COORDINATES_OUT_OF_RANGE"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_D2I_ECPKPARAMETERS_FAILURE), "D2I_ECPKPARAMETERS_FAILURE"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_EC_GROUP_NEW_BY_NAME_FAILURE), "EC_GROUP_NEW_BY_NAME_FAILURE"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_GF2M_NOT_SUPPORTED), "GF2M_NOT_SUPPORTED"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_GROUP2PKPARAMETERS_FAILURE), "GROUP2PKPARAMETERS_FAILURE"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_I2D_ECPKPARAMETERS_FAILURE), "I2D_ECPKPARAMETERS_FAILURE"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_INCOMPATIBLE_OBJECTS), "INCOMPATIBLE_OBJECTS"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_COMPRESSED_POINT), "INVALID_COMPRESSED_POINT"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_COMPRESSION_BIT), "INVALID_COMPRESSION_BIT"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_ENCODING), "INVALID_ENCODING"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_FIELD), "INVALID_FIELD"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_FORM), "INVALID_FORM"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_GROUP_ORDER), "INVALID_GROUP_ORDER"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_INVALID_PRIVATE_KEY), "INVALID_PRIVATE_KEY"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_MISSING_PARAMETERS), "MISSING_PARAMETERS"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_MISSING_PRIVATE_KEY), "MISSING_PRIVATE_KEY"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_NON_NAMED_CURVE), "NON_NAMED_CURVE"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_NOT_INITIALIZED), "NOT_INITIALIZED"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_PKPARAMETERS2GROUP_FAILURE), "PKPARAMETERS2GROUP_FAILURE"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_POINT_AT_INFINITY), "POINT_AT_INFINITY"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_POINT_IS_NOT_ON_CURVE), "POINT_IS_NOT_ON_CURVE"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_SLOT_FULL), "SLOT_FULL"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_UNDEFINED_GENERATOR), "UNDEFINED_GENERATOR"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_UNKNOWN_GROUP), "UNKNOWN_GROUP"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_UNKNOWN_ORDER), "UNKNOWN_ORDER"},
  {ERR_PACK(ERR_LIB_EC, 0, EC_R_WRONG_ORDER), "WRONG_ORDER"},
  {0, NULL},
};
