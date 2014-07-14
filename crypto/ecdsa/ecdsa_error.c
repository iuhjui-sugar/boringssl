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

#include <openssl/ecdsa.h>

const ERR_STRING_DATA ECDSA_error_string_data[] = {
  {ERR_PACK(ERR_LIB_ECDSA, ECDSA_F_ECDSA_do_sign_ex, 0), "ECDSA_do_sign_ex"},
  {ERR_PACK(ERR_LIB_ECDSA, ECDSA_F_ECDSA_do_verify, 0), "ECDSA_do_verify"},
  {ERR_PACK(ERR_LIB_ECDSA, ECDSA_F_ECDSA_sign_ex, 0), "ECDSA_sign_ex"},
  {ERR_PACK(ERR_LIB_ECDSA, ECDSA_F_ECDSA_sign_setup, 0), "ECDSA_sign_setup"},
  {ERR_PACK(ERR_LIB_ECDSA, ECDSA_F_digest_to_bn, 0), "digest_to_bn"},
  {ERR_PACK(ERR_LIB_ECDSA, ECDSA_F_ecdsa_sign_setup, 0), "ecdsa_sign_setup"},
  {ERR_PACK(ERR_LIB_ECDSA, 0, ECDSA_R_BAD_SIGNATURE), "BAD_SIGNATURE"},
  {ERR_PACK(ERR_LIB_ECDSA, 0, ECDSA_R_MISSING_PARAMETERS), "MISSING_PARAMETERS"},
  {ERR_PACK(ERR_LIB_ECDSA, 0, ECDSA_R_NEED_NEW_SETUP_VALUES), "NEED_NEW_SETUP_VALUES"},
  {ERR_PACK(ERR_LIB_ECDSA, 0, ECDSA_R_NOT_IMPLEMENTED), "NOT_IMPLEMENTED"},
  {ERR_PACK(ERR_LIB_ECDSA, 0, ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED), "RANDOM_NUMBER_GENERATION_FAILED"},
  {0, NULL},
};
