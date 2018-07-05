/* Copyright (c) 2016, Google Inc.
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

#include <functional>
#include <string>
#include <vector>

#include <assert.h>

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/stack.h>
#include <openssl/x509.h>

#include "../crypto/internal.h"

static const uint8_t kCertificateDER[] = {
    0x30, 0x82, 0x02, 0xff, 0x30, 0x82, 0x01, 0xe7, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x11, 0x00, 0xb1, 0x84, 0xee, 0x34, 0x99, 0x98, 0x76, 0xfb,
    0x6f, 0xb2, 0x15, 0xc8, 0x47, 0x79, 0x05, 0x9b, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30,
    0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x07,
    0x41, 0x63, 0x6d, 0x65, 0x20, 0x43, 0x6f, 0x30, 0x1e, 0x17, 0x0d, 0x31,
    0x35, 0x31, 0x31, 0x30, 0x37, 0x30, 0x30, 0x32, 0x34, 0x35, 0x36, 0x5a,
    0x17, 0x0d, 0x31, 0x36, 0x31, 0x31, 0x30, 0x36, 0x30, 0x30, 0x32, 0x34,
    0x35, 0x36, 0x5a, 0x30, 0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
    0x04, 0x0a, 0x13, 0x07, 0x41, 0x63, 0x6d, 0x65, 0x20, 0x43, 0x6f, 0x30,
    0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30,
    0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xce, 0x47, 0xcb, 0x11,
    0xbb, 0xd2, 0x9d, 0x8e, 0x9e, 0xd2, 0x1e, 0x14, 0xaf, 0xc7, 0xea, 0xb6,
    0xc9, 0x38, 0x2a, 0x6f, 0xb3, 0x7e, 0xfb, 0xbc, 0xfc, 0x59, 0x42, 0xb9,
    0x56, 0xf0, 0x4c, 0x3f, 0xf7, 0x31, 0x84, 0xbe, 0xac, 0x03, 0x9e, 0x71,
    0x91, 0x85, 0xd8, 0x32, 0xbd, 0x00, 0xea, 0xac, 0x65, 0xf6, 0x03, 0xc8,
    0x0f, 0x8b, 0xfd, 0x6e, 0x58, 0x88, 0x04, 0x41, 0x92, 0x74, 0xa6, 0x57,
    0x2e, 0x8e, 0x88, 0xd5, 0x3d, 0xda, 0x14, 0x3e, 0x63, 0x88, 0x22, 0xe3,
    0x53, 0xe9, 0xba, 0x39, 0x09, 0xac, 0xfb, 0xd0, 0x4c, 0xf2, 0x3c, 0x20,
    0xd6, 0x97, 0xe6, 0xed, 0xf1, 0x62, 0x1e, 0xe5, 0xc9, 0x48, 0xa0, 0xca,
    0x2e, 0x3c, 0x14, 0x5a, 0x82, 0xd4, 0xed, 0xb1, 0xe3, 0x43, 0xc1, 0x2a,
    0x59, 0xa5, 0xb9, 0xc8, 0x48, 0xa7, 0x39, 0x23, 0x74, 0xa7, 0x37, 0xb0,
    0x6f, 0xc3, 0x64, 0x99, 0x6c, 0xa2, 0x82, 0xc8, 0xf6, 0xdb, 0x86, 0x40,
    0xce, 0xd1, 0x85, 0x9f, 0xce, 0x69, 0xf4, 0x15, 0x2a, 0x23, 0xca, 0xea,
    0xb7, 0x7b, 0xdf, 0xfb, 0x43, 0x5f, 0xff, 0x7a, 0x49, 0x49, 0x0e, 0xe7,
    0x02, 0x51, 0x45, 0x13, 0xe8, 0x90, 0x64, 0x21, 0x0c, 0x26, 0x2b, 0x5d,
    0xfc, 0xe4, 0xb5, 0x86, 0x89, 0x43, 0x22, 0x4c, 0xf3, 0x3b, 0xf3, 0x09,
    0xc4, 0xa4, 0x10, 0x80, 0xf2, 0x46, 0xe2, 0x46, 0x8f, 0x76, 0x50, 0xbf,
    0xaf, 0x2b, 0x90, 0x1b, 0x78, 0xc7, 0xcf, 0xc1, 0x77, 0xd0, 0xfb, 0xa9,
    0xfb, 0xc9, 0x66, 0x5a, 0xc5, 0x9b, 0x31, 0x41, 0x67, 0x01, 0xbe, 0x33,
    0x10, 0xba, 0x05, 0x58, 0xed, 0x76, 0x53, 0xde, 0x5d, 0xc1, 0xe8, 0xbb,
    0x9f, 0xf1, 0xcd, 0xfb, 0xdf, 0x64, 0x7f, 0xd7, 0x18, 0xab, 0x0f, 0x94,
    0x28, 0x95, 0x4a, 0xcc, 0x6a, 0xa9, 0x50, 0xc7, 0x05, 0x47, 0x10, 0x41,
    0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x0e, 0x06,
    0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05,
    0xa0, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a,
    0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x30, 0x0c,
    0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00,
    0x30, 0x19, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x12, 0x30, 0x10, 0x82,
    0x0e, 0x66, 0x75, 0x7a, 0x7a, 0x2e, 0x62, 0x6f, 0x72, 0x69, 0x6e, 0x67,
    0x73, 0x73, 0x6c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x92,
    0xde, 0xef, 0x96, 0x06, 0x7b, 0xff, 0x71, 0x7d, 0x4e, 0xa0, 0x7d, 0xae,
    0xb8, 0x22, 0xb4, 0x2c, 0xf7, 0x96, 0x9c, 0x37, 0x1d, 0x8f, 0xe7, 0xd9,
    0x47, 0xff, 0x3f, 0xe9, 0x35, 0x95, 0x0e, 0xdd, 0xdc, 0x7f, 0xc8, 0x8a,
    0x1e, 0x36, 0x1d, 0x38, 0x47, 0xfc, 0x76, 0xd2, 0x1f, 0x98, 0xa1, 0x36,
    0xac, 0xc8, 0x70, 0x38, 0x0a, 0x3d, 0x51, 0x8d, 0x0f, 0x03, 0x1b, 0xef,
    0x62, 0xa1, 0xcb, 0x2b, 0x4a, 0x8c, 0x12, 0x2b, 0x54, 0x50, 0x9a, 0x6b,
    0xfe, 0xaf, 0xd9, 0xf6, 0xbf, 0x58, 0x11, 0x58, 0x5e, 0xe5, 0x86, 0x1e,
    0x3b, 0x6b, 0x30, 0x7e, 0x72, 0x89, 0xe8, 0x6b, 0x7b, 0xb7, 0xaf, 0xef,
    0x8b, 0xa9, 0x3e, 0xb0, 0xcd, 0x0b, 0xef, 0xb0, 0x0c, 0x96, 0x2b, 0xc5,
    0x3b, 0xd5, 0xf1, 0xc2, 0xae, 0x3a, 0x60, 0xd9, 0x0f, 0x75, 0x37, 0x55,
    0x4d, 0x62, 0xd2, 0xed, 0x96, 0xac, 0x30, 0x6b, 0xda, 0xa1, 0x48, 0x17,
    0x96, 0x23, 0x85, 0x9a, 0x57, 0x77, 0xe9, 0x22, 0xa2, 0x37, 0x03, 0xba,
    0x49, 0x77, 0x40, 0x3b, 0x76, 0x4b, 0xda, 0xc1, 0x04, 0x57, 0x55, 0x34,
    0x22, 0x83, 0x45, 0x29, 0xab, 0x2e, 0x11, 0xff, 0x0d, 0xab, 0x55, 0xb1,
    0xa7, 0x58, 0x59, 0x05, 0x25, 0xf9, 0x1e, 0x3d, 0xb7, 0xac, 0x04, 0x39,
    0x2c, 0xf9, 0xaf, 0xb8, 0x68, 0xfb, 0x8e, 0x35, 0x71, 0x32, 0xff, 0x70,
    0xe9, 0x46, 0x6d, 0x5c, 0x06, 0x90, 0x88, 0x23, 0x48, 0x0c, 0x50, 0xeb,
    0x0a, 0xa9, 0xae, 0xe8, 0xfc, 0xbe, 0xa5, 0x76, 0x94, 0xd7, 0x64, 0x22,
    0x38, 0x98, 0x17, 0xa4, 0x3a, 0xa7, 0x59, 0x9f, 0x1d, 0x3b, 0x75, 0x90,
    0x1a, 0x81, 0xef, 0x19, 0xfb, 0x2b, 0xb7, 0xa7, 0x64, 0x61, 0x22, 0xa4,
    0x6f, 0x7b, 0xfa, 0x58, 0xbb, 0x8c, 0x4e, 0x77, 0x67, 0xd0, 0x5d, 0x58,
    0x76, 0x8a, 0xbb,
};

static const uint8_t kRSAPrivateKeyDER[] = {
    0x30, 0x82, 0x04, 0xa5, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
    0xce, 0x47, 0xcb, 0x11, 0xbb, 0xd2, 0x9d, 0x8e, 0x9e, 0xd2, 0x1e, 0x14,
    0xaf, 0xc7, 0xea, 0xb6, 0xc9, 0x38, 0x2a, 0x6f, 0xb3, 0x7e, 0xfb, 0xbc,
    0xfc, 0x59, 0x42, 0xb9, 0x56, 0xf0, 0x4c, 0x3f, 0xf7, 0x31, 0x84, 0xbe,
    0xac, 0x03, 0x9e, 0x71, 0x91, 0x85, 0xd8, 0x32, 0xbd, 0x00, 0xea, 0xac,
    0x65, 0xf6, 0x03, 0xc8, 0x0f, 0x8b, 0xfd, 0x6e, 0x58, 0x88, 0x04, 0x41,
    0x92, 0x74, 0xa6, 0x57, 0x2e, 0x8e, 0x88, 0xd5, 0x3d, 0xda, 0x14, 0x3e,
    0x63, 0x88, 0x22, 0xe3, 0x53, 0xe9, 0xba, 0x39, 0x09, 0xac, 0xfb, 0xd0,
    0x4c, 0xf2, 0x3c, 0x20, 0xd6, 0x97, 0xe6, 0xed, 0xf1, 0x62, 0x1e, 0xe5,
    0xc9, 0x48, 0xa0, 0xca, 0x2e, 0x3c, 0x14, 0x5a, 0x82, 0xd4, 0xed, 0xb1,
    0xe3, 0x43, 0xc1, 0x2a, 0x59, 0xa5, 0xb9, 0xc8, 0x48, 0xa7, 0x39, 0x23,
    0x74, 0xa7, 0x37, 0xb0, 0x6f, 0xc3, 0x64, 0x99, 0x6c, 0xa2, 0x82, 0xc8,
    0xf6, 0xdb, 0x86, 0x40, 0xce, 0xd1, 0x85, 0x9f, 0xce, 0x69, 0xf4, 0x15,
    0x2a, 0x23, 0xca, 0xea, 0xb7, 0x7b, 0xdf, 0xfb, 0x43, 0x5f, 0xff, 0x7a,
    0x49, 0x49, 0x0e, 0xe7, 0x02, 0x51, 0x45, 0x13, 0xe8, 0x90, 0x64, 0x21,
    0x0c, 0x26, 0x2b, 0x5d, 0xfc, 0xe4, 0xb5, 0x86, 0x89, 0x43, 0x22, 0x4c,
    0xf3, 0x3b, 0xf3, 0x09, 0xc4, 0xa4, 0x10, 0x80, 0xf2, 0x46, 0xe2, 0x46,
    0x8f, 0x76, 0x50, 0xbf, 0xaf, 0x2b, 0x90, 0x1b, 0x78, 0xc7, 0xcf, 0xc1,
    0x77, 0xd0, 0xfb, 0xa9, 0xfb, 0xc9, 0x66, 0x5a, 0xc5, 0x9b, 0x31, 0x41,
    0x67, 0x01, 0xbe, 0x33, 0x10, 0xba, 0x05, 0x58, 0xed, 0x76, 0x53, 0xde,
    0x5d, 0xc1, 0xe8, 0xbb, 0x9f, 0xf1, 0xcd, 0xfb, 0xdf, 0x64, 0x7f, 0xd7,
    0x18, 0xab, 0x0f, 0x94, 0x28, 0x95, 0x4a, 0xcc, 0x6a, 0xa9, 0x50, 0xc7,
    0x05, 0x47, 0x10, 0x41, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,
    0x01, 0x00, 0xa8, 0x47, 0xb9, 0x4a, 0x06, 0x47, 0x93, 0x71, 0x3d, 0xef,
    0x7b, 0xca, 0xb4, 0x7c, 0x0a, 0xe6, 0x82, 0xd0, 0xe7, 0x0d, 0xa9, 0x08,
    0xf6, 0xa4, 0xfd, 0xd8, 0x73, 0xae, 0x6f, 0x56, 0x29, 0x5e, 0x25, 0x72,
    0xa8, 0x30, 0x44, 0x73, 0xcf, 0x56, 0x26, 0xb9, 0x61, 0xde, 0x42, 0x81,
    0xf4, 0xf0, 0x1f, 0x5d, 0xcb, 0x47, 0xf2, 0x26, 0xe9, 0xe0, 0x93, 0x28,
    0xa3, 0x10, 0x3b, 0x42, 0x1e, 0x51, 0x11, 0x12, 0x06, 0x5e, 0xaf, 0xce,
    0xb0, 0xa5, 0x14, 0xdd, 0x82, 0x58, 0xa1, 0xa4, 0x12, 0xdf, 0x65, 0x1d,
    0x51, 0x70, 0x64, 0xd5, 0x58, 0x68, 0x11, 0xa8, 0x6a, 0x23, 0xc2, 0xbf,
    0xa1, 0x25, 0x24, 0x47, 0xb3, 0xa4, 0x3c, 0x83, 0x96, 0xb7, 0x1f, 0xf4,
    0x44, 0xd4, 0xd1, 0xe9, 0xfc, 0x33, 0x68, 0x5e, 0xe2, 0x68, 0x99, 0x9c,
    0x91, 0xe8, 0x72, 0xc9, 0xd7, 0x8c, 0x80, 0x20, 0x8e, 0x77, 0x83, 0x4d,
    0xe4, 0xab, 0xf9, 0x74, 0xa1, 0xdf, 0xd3, 0xc0, 0x0d, 0x5b, 0x05, 0x51,
    0xc2, 0x6f, 0xb2, 0x91, 0x02, 0xec, 0xc0, 0x02, 0x1a, 0x5c, 0x91, 0x05,
    0xf1, 0xe3, 0xfa, 0x65, 0xc2, 0xad, 0x24, 0xe6, 0xe5, 0x3c, 0xb6, 0x16,
    0xf1, 0xa1, 0x67, 0x1a, 0x9d, 0x37, 0x56, 0xbf, 0x01, 0xd7, 0x3b, 0x35,
    0x30, 0x57, 0x73, 0xf4, 0xf0, 0x5e, 0xa7, 0xe8, 0x0a, 0xc1, 0x94, 0x17,
    0xcf, 0x0a, 0xbd, 0xf5, 0x31, 0xa7, 0x2d, 0xf7, 0xf5, 0xd9, 0x8c, 0xc2,
    0x01, 0xbd, 0xda, 0x16, 0x8e, 0xb9, 0x30, 0x40, 0xa6, 0x6e, 0xbd, 0xcd,
    0x4d, 0x84, 0x67, 0x4e, 0x0b, 0xce, 0xd5, 0xef, 0xf8, 0x08, 0x63, 0x02,
    0xc6, 0xc7, 0xf7, 0x67, 0x92, 0xe2, 0x23, 0x9d, 0x27, 0x22, 0x1d, 0xc6,
    0x67, 0x5e, 0x66, 0xbf, 0x03, 0xb8, 0xa9, 0x67, 0xd4, 0x39, 0xd8, 0x75,
    0xfa, 0xe8, 0xed, 0x56, 0xb8, 0x81, 0x02, 0x81, 0x81, 0x00, 0xf7, 0x46,
    0x68, 0xc6, 0x13, 0xf8, 0xba, 0x0f, 0x83, 0xdb, 0x05, 0xa8, 0x25, 0x00,
    0x70, 0x9c, 0x9e, 0x8b, 0x12, 0x34, 0x0d, 0x96, 0xcf, 0x0d, 0x98, 0x9b,
    0x8d, 0x9c, 0x96, 0x78, 0xd1, 0x3c, 0x01, 0x8c, 0xb9, 0x35, 0x5c, 0x20,
    0x42, 0xb4, 0x38, 0xe3, 0xd6, 0x54, 0xe7, 0x55, 0xd6, 0x26, 0x8a, 0x0c,
    0xf6, 0x1f, 0xe0, 0x04, 0xc1, 0x22, 0x42, 0x19, 0x61, 0xc4, 0x94, 0x7c,
    0x07, 0x2e, 0x80, 0x52, 0xfe, 0x8d, 0xe6, 0x92, 0x3a, 0x91, 0xfe, 0x72,
    0x99, 0xe1, 0x2a, 0x73, 0x76, 0xb1, 0x24, 0x20, 0x67, 0xde, 0x28, 0xcb,
    0x0e, 0xe6, 0x52, 0xb5, 0xfa, 0xfb, 0x8b, 0x1e, 0x6a, 0x1d, 0x09, 0x26,
    0xb9, 0xa7, 0x61, 0xba, 0xf8, 0x79, 0xd2, 0x66, 0x57, 0x28, 0xd7, 0x31,
    0xb5, 0x0b, 0x27, 0x19, 0x1e, 0x6f, 0x46, 0xfc, 0x54, 0x95, 0xeb, 0x78,
    0x01, 0xb6, 0xd9, 0x79, 0x5a, 0x4d, 0x02, 0x81, 0x81, 0x00, 0xd5, 0x8f,
    0x16, 0x53, 0x2f, 0x57, 0x93, 0xbf, 0x09, 0x75, 0xbf, 0x63, 0x40, 0x3d,
    0x27, 0xfd, 0x23, 0x21, 0xde, 0x9b, 0xe9, 0x73, 0x3f, 0x49, 0x02, 0xd2,
    0x38, 0x96, 0xcf, 0xc3, 0xba, 0x92, 0x07, 0x87, 0x52, 0xa9, 0x35, 0xe3,
    0x0c, 0xe4, 0x2f, 0x05, 0x7b, 0x37, 0xa5, 0x40, 0x9c, 0x3b, 0x94, 0xf7,
    0xad, 0xa0, 0xee, 0x3a, 0xa8, 0xfb, 0x1f, 0x11, 0x1f, 0xd8, 0x9a, 0x80,
    0x42, 0x3d, 0x7f, 0xa4, 0xb8, 0x9a, 0xaa, 0xea, 0x72, 0xc1, 0xe3, 0xed,
    0x06, 0x60, 0x92, 0x37, 0xf9, 0xba, 0xfb, 0x9e, 0xed, 0x05, 0xa6, 0xd4,
    0x72, 0x68, 0x4f, 0x63, 0xfe, 0xd6, 0x10, 0x0d, 0x4f, 0x0a, 0x93, 0xc6,
    0xb9, 0xd7, 0xaf, 0xfd, 0xd9, 0x57, 0x7d, 0xcb, 0x75, 0xe8, 0x93, 0x2b,
    0xae, 0x4f, 0xea, 0xd7, 0x30, 0x0b, 0x58, 0x44, 0x82, 0x0f, 0x84, 0x5d,
    0x62, 0x11, 0x78, 0xea, 0x5f, 0xc5, 0x02, 0x81, 0x81, 0x00, 0x82, 0x0c,
    0xc1, 0xe6, 0x0b, 0x72, 0xf1, 0x48, 0x5f, 0xac, 0xbd, 0x98, 0xe5, 0x7d,
    0x09, 0xbd, 0x15, 0x95, 0x47, 0x09, 0xa1, 0x6c, 0x03, 0x91, 0xbf, 0x05,
    0x70, 0xc1, 0x3e, 0x52, 0x64, 0x99, 0x0e, 0xa7, 0x98, 0x70, 0xfb, 0xf6,
    0xeb, 0x9e, 0x25, 0x9d, 0x8e, 0x88, 0x30, 0xf2, 0xf0, 0x22, 0x6c, 0xd0,
    0xcc, 0x51, 0x8f, 0x5c, 0x70, 0xc7, 0x37, 0xc4, 0x69, 0xab, 0x1d, 0xfc,
    0xed, 0x3a, 0x03, 0xbb, 0xa2, 0xad, 0xb6, 0xea, 0x89, 0x6b, 0x67, 0x4b,
    0x96, 0xaa, 0xd9, 0xcc, 0xc8, 0x4b, 0xfa, 0x18, 0x21, 0x08, 0xb2, 0xa3,
    0xb9, 0x3e, 0x61, 0x99, 0xdc, 0x5a, 0x97, 0x9c, 0x73, 0x6a, 0xb9, 0xf9,
    0x68, 0x03, 0x24, 0x5f, 0x55, 0x77, 0x9c, 0xb4, 0xbe, 0x7a, 0x78, 0x53,
    0x68, 0x48, 0x69, 0x53, 0xc8, 0xb1, 0xf5, 0xbf, 0x98, 0x2d, 0x11, 0x1e,
    0x98, 0xa8, 0x36, 0x50, 0xa0, 0xb1, 0x02, 0x81, 0x81, 0x00, 0x90, 0x88,
    0x30, 0x71, 0xc7, 0xfe, 0x9b, 0x6d, 0x95, 0x37, 0x6d, 0x79, 0xfc, 0x85,
    0xe7, 0x44, 0x78, 0xbc, 0x79, 0x6e, 0x47, 0x86, 0xc9, 0xf3, 0xdd, 0xc6,
    0xec, 0xa9, 0x94, 0x9f, 0x40, 0xeb, 0x87, 0xd0, 0xdb, 0xee, 0xcd, 0x1b,
    0x87, 0x23, 0xff, 0x76, 0xd4, 0x37, 0x8a, 0xcd, 0xb9, 0x6e, 0xd1, 0x98,
    0xf6, 0x97, 0x8d, 0xe3, 0x81, 0x6d, 0xc3, 0x4e, 0xd1, 0xa0, 0xc4, 0x9f,
    0xbd, 0x34, 0xe5, 0xe8, 0x53, 0x4f, 0xca, 0x10, 0xb5, 0xed, 0xe7, 0x16,
    0x09, 0x54, 0xde, 0x60, 0xa7, 0xd1, 0x16, 0x6e, 0x2e, 0xb7, 0xbe, 0x7a,
    0xd5, 0x9b, 0x26, 0xef, 0xe4, 0x0e, 0x77, 0xfa, 0xa9, 0xdd, 0xdc, 0xb9,
    0x88, 0x19, 0x23, 0x70, 0xc7, 0xe1, 0x60, 0xaf, 0x8c, 0x73, 0x04, 0xf7,
    0x71, 0x17, 0x81, 0x36, 0x75, 0xbb, 0x97, 0xd7, 0x75, 0xb6, 0x8e, 0xbc,
    0xac, 0x9c, 0x6a, 0x9b, 0x24, 0x89, 0x02, 0x81, 0x80, 0x5a, 0x2b, 0xc7,
    0x6b, 0x8c, 0x65, 0xdb, 0x04, 0x73, 0xab, 0x25, 0xe1, 0x5b, 0xbc, 0x3c,
    0xcf, 0x5a, 0x3c, 0x04, 0xae, 0x97, 0x2e, 0xfd, 0xa4, 0x97, 0x1f, 0x05,
    0x17, 0x27, 0xac, 0x7c, 0x30, 0x85, 0xb4, 0x82, 0x3f, 0x5b, 0xb7, 0x94,
    0x3b, 0x7f, 0x6c, 0x0c, 0xc7, 0x16, 0xc6, 0xa0, 0xbd, 0x80, 0xb0, 0x81,
    0xde, 0xa0, 0x23, 0xa6, 0xf6, 0x75, 0x33, 0x51, 0x35, 0xa2, 0x75, 0x55,
    0x70, 0x4d, 0x42, 0xbb, 0xcf, 0x54, 0xe4, 0xdb, 0x2d, 0x88, 0xa0, 0x7a,
    0xf2, 0x17, 0xa7, 0xdd, 0x13, 0x44, 0x9f, 0x5f, 0x6b, 0x2c, 0x42, 0x42,
    0x8b, 0x13, 0x4d, 0xf9, 0x5b, 0xf8, 0x33, 0x42, 0xd9, 0x9e, 0x50, 0x1c,
    0x7c, 0xbc, 0xfa, 0x62, 0x85, 0x0b, 0xcf, 0x99, 0xda, 0x9e, 0x04, 0x90,
    0xb2, 0xc6, 0xb2, 0x0a, 0x2a, 0x7c, 0x6d, 0x6a, 0x40, 0xfc, 0xf5, 0x50,
    0x98, 0x46, 0x89, 0x82, 0x40,
};

struct GlobalState {
  GlobalState() {
    const uint8_t *bufp = kRSAPrivateKeyDER;
    RSA *privkey = d2i_RSAPrivateKey(NULL, &bufp, sizeof(kRSAPrivateKeyDER));
    assert(privkey != nullptr);

    pkey_.reset(EVP_PKEY_new());
    EVP_PKEY_assign_RSA(pkey_.get(), privkey);

    bufp = kCertificateDER;
    cert_.reset(d2i_X509(NULL, &bufp, sizeof(kCertificateDER)));
    assert(cert_.get() != nullptr);

    certs_.reset(sk_X509_new_null());
    bssl::PushToStack(certs_.get(), bssl::UpRef(cert_));
  }

  bssl::UniquePtr<EVP_PKEY> pkey_;
  bssl::UniquePtr<X509> cert_;
  bssl::UniquePtr<STACK_OF(X509)> certs_;
};

static GlobalState g_state;

static bool GetString(std::string *out, CBS *cbs) {
  CBS str;
  if (!CBS_get_u8_length_prefixed(cbs, &str)) {
    return false;
  }

  out->assign(reinterpret_cast<const char *>(CBS_data(&str)), CBS_len(&str));
  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  constexpr size_t kMaxExpensiveAPIs = 100;
  unsigned expensive_api_count = 0;

  const std::function<void(SSL_CTX *, CBS *)> kAPIs[] = {
      [](SSL_CTX *ctx, CBS *cbs) {
        uint8_t b;
        if (!CBS_get_u8(cbs, &b)) {
          return;
        }
        SSL_CTX_set_quiet_shutdown(ctx, b);
      },
      [](SSL_CTX *ctx, CBS *cbs) { SSL_CTX_get_quiet_shutdown(ctx); },
      [](SSL_CTX *ctx, CBS *cbs) {
        uint16_t version;
        if (!CBS_get_u16(cbs, &version)) {
          return;
        }
        SSL_CTX_set_min_proto_version(ctx, version);
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        uint16_t version;
        if (!CBS_get_u16(cbs, &version)) {
          return;
        }
        SSL_CTX_set_max_proto_version(ctx, version);
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        uint32_t options;
        if (!CBS_get_u32(cbs, &options)) {
          return;
        }
        SSL_CTX_set_options(ctx, options);
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        uint32_t options;
        if (!CBS_get_u32(cbs, &options)) {
          return;
        }
        SSL_CTX_clear_options(ctx, options);
      },
      [](SSL_CTX *ctx, CBS *cbs) { SSL_CTX_get_options(ctx); },
      [](SSL_CTX *ctx, CBS *cbs) {
        uint32_t mode;
        if (!CBS_get_u32(cbs, &mode)) {
          return;
        }
        SSL_CTX_set_mode(ctx, mode);
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        uint32_t mode;
        if (!CBS_get_u32(cbs, &mode)) {
          return;
        }
        SSL_CTX_clear_mode(ctx, mode);
      },
      [](SSL_CTX *ctx, CBS *cbs) { SSL_CTX_get_mode(ctx); },
      [](SSL_CTX *ctx, CBS *cbs) {
        SSL_CTX_use_certificate(ctx, g_state.cert_.get());
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        SSL_CTX_use_PrivateKey(ctx, g_state.pkey_.get());
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        SSL_CTX_set1_chain(ctx, g_state.certs_.get());
      },
      [&](SSL_CTX *ctx, CBS *cbs) {
        // Avoid an unbounded certificate chain.
        if (++expensive_api_count >= kMaxExpensiveAPIs) {
          return;
        }

        SSL_CTX_add1_chain_cert(ctx, g_state.cert_.get());
      },
      [](SSL_CTX *ctx, CBS *cbs) { SSL_CTX_clear_chain_certs(ctx); },
      [](SSL_CTX *ctx, CBS *cbs) { SSL_CTX_clear_extra_chain_certs(ctx); },
      [](SSL_CTX *ctx, CBS *cbs) { SSL_CTX_check_private_key(ctx); },
      [](SSL_CTX *ctx, CBS *cbs) { SSL_CTX_get0_certificate(ctx); },
      [](SSL_CTX *ctx, CBS *cbs) { SSL_CTX_get0_privatekey(ctx); },
      [](SSL_CTX *ctx, CBS *cbs) {
        STACK_OF(X509) * chains;
        SSL_CTX_get0_chain_certs(ctx, &chains);
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        std::string sct_data;
        if (!GetString(&sct_data, cbs)) {
          return;
        }

        SSL_CTX_set_signed_cert_timestamp_list(
            ctx, reinterpret_cast<const uint8_t *>(sct_data.data()),
            sct_data.size());
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        std::string ocsp_data;
        if (!GetString(&ocsp_data, cbs)) {
          return;
        }

        SSL_CTX_set_ocsp_response(
            ctx, reinterpret_cast<const uint8_t *>(ocsp_data.data()),
            ocsp_data.size());
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        std::string signing_algos;
        if (!GetString(&signing_algos, cbs)) {
          return;
        }

        SSL_CTX_set_signing_algorithm_prefs(
            ctx, reinterpret_cast<const uint16_t *>(signing_algos.data()),
            signing_algos.size() / sizeof(uint16_t));
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        std::string ciphers;
        if (!GetString(&ciphers, cbs)) {
          return;
        }
        SSL_CTX_set_strict_cipher_list(ctx, ciphers.c_str());
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        std::string ciphers;
        if (!GetString(&ciphers, cbs)) {
          return;
        }
        SSL_CTX_set_cipher_list(ctx, ciphers.c_str());
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        std::string verify_algos;
        if (!GetString(&verify_algos, cbs)) {
          return;
        }

        SSL_CTX_set_verify_algorithm_prefs(
            ctx, reinterpret_cast<const uint16_t *>(verify_algos.data()),
            verify_algos.size() / sizeof(uint16_t));
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        std::string ciphers;
        if (!GetString(&ciphers, cbs)) {
          return;
        }
        SSL_CTX_set_session_id_context(
            ctx, reinterpret_cast<const uint8_t *>(ciphers.data()),
            ciphers.size());
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        uint32_t size;
        if (!CBS_get_u32(cbs, &size)) {
          return;
        }
        SSL_CTX_sess_set_cache_size(ctx, size);
      },
      [](SSL_CTX *ctx, CBS *cbs) { SSL_CTX_sess_get_cache_size(ctx); },
      [](SSL_CTX *ctx, CBS *cbs) { SSL_CTX_sess_number(ctx); },
      [](SSL_CTX *ctx, CBS *cbs) {
        uint32_t time;
        if (!CBS_get_u32(cbs, &time)) {
          return;
        }
        SSL_CTX_flush_sessions(ctx, time);
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        std::string keys;
        if (!GetString(&keys, cbs)) {
          return;
        }
        SSL_CTX_set_tlsext_ticket_keys(
            ctx, reinterpret_cast<const uint8_t *>(keys.data()), keys.size());
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        std::string curves;
        if (!GetString(&curves, cbs)) {
          return;
        }
        SSL_CTX_set1_curves(ctx, reinterpret_cast<const int *>(curves.data()),
                            curves.size() / sizeof(int));
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        std::string curves;
        if (!GetString(&curves, cbs)) {
          return;
        }
        SSL_CTX_set1_curves_list(ctx, curves.c_str());
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        SSL_CTX_enable_signed_cert_timestamps(ctx);
      },
      [](SSL_CTX *ctx, CBS *cbs) { SSL_CTX_enable_ocsp_stapling(ctx); },
      [&](SSL_CTX *ctx, CBS *cbs) {
        // Avoid an unbounded client CA list.
        if (++expensive_api_count >= kMaxExpensiveAPIs) {
          return;
        }

        SSL_CTX_add_client_CA(ctx, g_state.cert_.get());
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        std::string protos;
        if (!GetString(&protos, cbs)) {
          return;
        }
        SSL_CTX_set_alpn_protos(
            ctx, reinterpret_cast<const uint8_t *>(protos.data()),
            protos.size());
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        std::string profiles;
        if (!GetString(&profiles, cbs)) {
          return;
        }
        SSL_CTX_set_srtp_profiles(ctx, profiles.c_str());
      },
      [](SSL_CTX *ctx, CBS *cbs) { SSL_CTX_get_max_cert_list(ctx); },
      [](SSL_CTX *ctx, CBS *cbs) {
        uint32_t size;
        if (!CBS_get_u32(cbs, &size)) {
          return;
        }
        SSL_CTX_set_max_cert_list(ctx, size);
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        uint32_t size;
        if (!CBS_get_u32(cbs, &size)) {
          return;
        }
        SSL_CTX_set_max_send_fragment(ctx, size);
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        uint8_t b;
        if (!CBS_get_u8(cbs, &b)) {
          return;
        }
        SSL_CTX_set_retain_only_sha256_of_client_certs(ctx, b);
      },
      [](SSL_CTX *ctx, CBS *cbs) {
        uint8_t b;
        if (!CBS_get_u8(cbs, &b)) {
          return;
        }
        SSL_CTX_set_grease_enabled(ctx, b);
      },
  };

  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));

  // If the number of functions exceeds this limit then the code needs to do
  // more than sample a single uint8_t to pick the function.
  static_assert(OPENSSL_ARRAY_SIZE(kAPIs) < 256, "kAPIs too large");

  CBS cbs;
  CBS_init(&cbs, buf, len);

  for (;;) {
    uint8_t index;
    if (!CBS_get_u8(&cbs, &index)) {
      break;
    }

    kAPIs[index % OPENSSL_ARRAY_SIZE(kAPIs)](ctx.get(), &cbs);
  }

  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  ERR_clear_error();

  return 0;
}
