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

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <memory>

#include <gtest/gtest.h>

#include <openssl/crypto.h>
#include <openssl/chacha.h>

#include "internal.h"
#include "../internal.h"
#include "../test/abi_test.h"
#include "../test/test_util.h"


static const uint8_t kKey[32] = {
    0x98, 0xbe, 0xf1, 0x46, 0x9b, 0xe7, 0x26, 0x98, 0x37, 0xa4, 0x5b,
    0xfb, 0xc9, 0x2a, 0x5a, 0x6a, 0xc7, 0x62, 0x50, 0x7c, 0xf9, 0x64,
    0x43, 0xbf, 0x33, 0xb9, 0x6b, 0x1b, 0xd4, 0xc6, 0xf8, 0xf6,
};

static const uint8_t kNonce[12] = {
    0x44, 0xe7, 0x92, 0xd6, 0x33, 0x35, 0xab, 0xb1, 0x58, 0x2e, 0x92, 0x53,
};

static uint32_t kCounter = 42;

static const uint8_t kInput[] = {
    0x58, 0x28, 0xd5, 0x30, 0x36, 0x2c, 0x60, 0x55, 0x29, 0xf8, 0xe1, 0x8c,
    0xae, 0x15, 0x15, 0x26, 0xf2, 0x3a, 0x73, 0xa0, 0xf3, 0x12, 0xa3, 0x88,
    0x5f, 0x2b, 0x74, 0x23, 0x3d, 0xc9, 0x05, 0x23, 0xc6, 0x54, 0x49, 0x1e,
    0x44, 0x88, 0x14, 0xd9, 0xda, 0x37, 0x15, 0xdc, 0xb7, 0xe4, 0x23, 0xb3,
    0x9d, 0x7e, 0x16, 0x68, 0x35, 0xfc, 0x02, 0x6d, 0xcc, 0x8a, 0xe5, 0xdd,
    0x5f, 0xe4, 0xd2, 0x56, 0x6f, 0x12, 0x9c, 0x9c, 0x7d, 0x6a, 0x38, 0x48,
    0xbd, 0xdf, 0xd9, 0xac, 0x1b, 0xa2, 0x4d, 0xc5, 0x43, 0x04, 0x3c, 0xd7,
    0x99, 0xe1, 0xa7, 0x13, 0x9c, 0x51, 0xc2, 0x6d, 0xf9, 0xcf, 0x07, 0x3b,
    0xe4, 0xbf, 0x93, 0xa3, 0xa9, 0xb4, 0xc5, 0xf0, 0x1a, 0xe4, 0x8d, 0x5f,
    0xc6, 0xc4, 0x7c, 0x69, 0x7a, 0xde, 0x1a, 0xc1, 0xc9, 0xcf, 0xc2, 0x4e,
    0x7a, 0x25, 0x2c, 0x32, 0xe9, 0x17, 0xba, 0x68, 0xf1, 0x37, 0x5d, 0x62,
    0x84, 0x46, 0xf5, 0x80, 0x7f, 0x1a, 0x71, 0xf7, 0xbe, 0x72, 0x4b, 0xb8,
    0x1c, 0xfe, 0x3e, 0xbd, 0xae, 0x0d, 0x73, 0x0d, 0x87, 0x4a, 0x31, 0xc3,
    0x3d, 0x46, 0x6f, 0xb3, 0xd7, 0x6b, 0xe3, 0xb8, 0x70, 0x17, 0x8e, 0x7a,
    0x6a, 0x0e, 0xbf, 0xa8, 0xbc, 0x2b, 0xdb, 0xfa, 0x4f, 0xb6, 0x26, 0x20,
    0xee, 0x63, 0xf0, 0x6d, 0x26, 0xac, 0x6a, 0x18, 0x37, 0x6e, 0x59, 0x81,
    0xd1, 0x60, 0xe6, 0x40, 0xd5, 0x6d, 0x68, 0xba, 0x8b, 0x65, 0x4a, 0xf9,
    0xf1, 0xae, 0x56, 0x24, 0x8f, 0xe3, 0x8e, 0xe7, 0x7e, 0x6f, 0xcf, 0x92,
    0xdf, 0xa9, 0x75, 0x3a, 0xd6, 0x2e, 0x1c, 0xaf, 0xf2, 0xd6, 0x8b, 0x39,
    0xad, 0xd2, 0x5d, 0xfb, 0xd7, 0xdf, 0x05, 0x57, 0x0d, 0xf7, 0xf6, 0x8f,
    0x2d, 0x14, 0xb0, 0x4e, 0x1a, 0x3c, 0x77, 0x04, 0xcd, 0x3c, 0x5c, 0x58,
    0x52, 0x10, 0x6f, 0xcf, 0x5c, 0x03, 0xc8, 0x5f, 0x85, 0x2b, 0x05, 0x82,
    0x60, 0xda, 0xcc, 0xcd, 0xd6, 0x88, 0xbf, 0xc0, 0x10, 0xb3, 0x6f, 0x54,
    0x54, 0x42, 0xbc, 0x4b, 0x77, 0x21, 0x4d, 0xee, 0x87, 0x45, 0x06, 0x4c,
    0x60, 0x38, 0xd2, 0x7e, 0x1d, 0x30, 0x6c, 0x55, 0xf0, 0x38, 0x80, 0x1c,
    0xde, 0x3d, 0xea, 0x68, 0x3e, 0xf6, 0x3e, 0x59, 0xcf, 0x0d, 0x08, 0xae,
    0x8c, 0x02, 0x0b, 0xc1, 0x72, 0x6a, 0xb4, 0x6d, 0xf3, 0xf7, 0xb3, 0xef,
    0x3a, 0xb1, 0x06, 0xf2, 0xf4, 0xd6, 0x69, 0x7b, 0x3e, 0xa2, 0x16, 0x31,
    0x31, 0x79, 0xb6, 0x33, 0xa9, 0xca, 0x8a, 0xa8, 0xbe, 0xf3, 0xe9, 0x38,
    0x28, 0xd1, 0xe1, 0x3b, 0x4e, 0x2e, 0x47, 0x35, 0xa4, 0x61, 0x14, 0x1e,
    0x42, 0x2c, 0x49, 0x55, 0xea, 0xe3, 0xb3, 0xce, 0x39, 0xd3, 0xb3, 0xef,
    0x4a, 0x4d, 0x78, 0x49, 0xbd, 0xf6, 0x7c, 0x0a, 0x2c, 0xd3, 0x26, 0xcb,
    0xd9, 0x6a, 0xad, 0x63, 0x93, 0xa7, 0x29, 0x92, 0xdc, 0x1f, 0xaf, 0x61,
    0x82, 0x80, 0x74, 0xb2, 0x9c, 0x4a, 0x86, 0x73, 0x50, 0xd8, 0xd1, 0xff,
    0xee, 0x1a, 0xe2, 0xdd, 0xa2, 0x61, 0xbd, 0x10, 0xc3, 0x5f, 0x67, 0x9f,
    0x29, 0xe4, 0xd3, 0x70, 0xe5, 0x67, 0x3a, 0xd2, 0x20, 0x00, 0xcc, 0x25,
    0x15, 0x96, 0x54, 0x45, 0x85, 0xed, 0x82, 0x88, 0x3b, 0x9f, 0x3b, 0xc3,
    0x04, 0xd4, 0x23, 0xb1, 0x0d, 0xdc, 0xc8, 0x26, 0x9d, 0x28, 0xb3, 0x25,
    0x4d, 0x52, 0xe5, 0x33, 0xf3, 0xed, 0x2c, 0xb8, 0x1a, 0xcf, 0xc3, 0x52,
    0xb4, 0x2f, 0xc7, 0x79, 0x96, 0x14, 0x7d, 0x72, 0x27, 0x72, 0x85, 0xea,
    0x6d, 0x41, 0xa0, 0x22, 0x13, 0x6d, 0x06, 0x83, 0xa4, 0xdd, 0x0f, 0x69,
    0xd2, 0x01, 0xcd, 0xc6, 0xb8, 0x64, 0x5c, 0x2c, 0x79, 0xd1, 0xc7, 0xd3,
    0x31, 0xdb, 0x2c, 0xff, 0xda, 0xd0, 0x69, 0x31, 0xad, 0x83, 0x5f, 0xed,
    0x6a, 0x97, 0xe4, 0x00, 0x43, 0xb0, 0x2e, 0x97, 0xae, 0x00, 0x5f, 0x5c,
    0xb9, 0xe8, 0x39, 0x80, 0x10, 0xca, 0x0c, 0xfa, 0xf0, 0xb5, 0xcd, 0xaa,
    0x27, 0x11, 0x60, 0xd9, 0x21, 0x86, 0x93, 0x91, 0x9f, 0x2d, 0x1a, 0x8e,
    0xde, 0x0b, 0xb5, 0xcb, 0x05, 0x24, 0x30, 0x45, 0x4d, 0x11, 0x75, 0xfd,
    0xe5, 0xa0, 0xa9, 0x4e, 0x3a, 0x8c, 0x3b, 0x52, 0x5a, 0x37, 0x18, 0x05,
    0x4a, 0x7a, 0x09, 0x6a, 0xe6, 0xd5, 0xa9, 0xa6, 0x71, 0x47, 0x4c, 0x50,
    0xe1, 0x3e, 0x8a, 0x21, 0x2b, 0x4f, 0x0e, 0xe3, 0xcb, 0x72, 0xc5, 0x28,
    0x3e, 0x5a, 0x33, 0xec, 0x48, 0x92, 0x2e, 0xa1, 0x24, 0x57, 0x09, 0x0f,
    0x01, 0x85, 0x3b, 0x34, 0x39, 0x7e, 0xc7, 0x90, 0x62, 0xe2, 0xdc, 0x5d,
    0x0a, 0x2c, 0x51, 0x26, 0x95, 0x3a, 0x95, 0x92, 0xa5, 0x39, 0x8f, 0x0c,
    0x83, 0x0b, 0x9d, 0x38, 0xab, 0x98, 0x2a, 0xc4, 0x01, 0xc4, 0x0d, 0x77,
    0x13, 0xcb, 0xca, 0xf1, 0x28, 0x31, 0x52, 0x75, 0x27, 0x2c, 0xf0, 0x04,
    0x86, 0xc8, 0xf3, 0x3d, 0xf2, 0x9d, 0x8f, 0x55, 0x52, 0x40, 0x3f, 0xaa,
    0x22, 0x7f, 0xe7, 0x69, 0x3b, 0xee, 0x44, 0x09, 0xde, 0xff, 0xb0, 0x69,
    0x3a, 0xae, 0x74, 0xe9, 0x9d, 0x33, 0xae, 0x8b, 0x6d, 0x60, 0x04, 0xff,
    0x53, 0x3f, 0x88, 0xe9, 0x63, 0x9b, 0xb1, 0x6d, 0x2c, 0x22, 0x15, 0x5a,
    0x15, 0xd9, 0xe5, 0xcb, 0x03, 0x78, 0x3c, 0xca, 0x59, 0x8c, 0xc8, 0xc2,
    0x86, 0xff, 0xd2, 0x79, 0xd6, 0xc6, 0xec, 0x5b, 0xbb, 0xa0, 0xae, 0x01,
    0x20, 0x09, 0x2e, 0x38, 0x5d, 0xda, 0x5d, 0xe0, 0x59, 0x4e, 0xe5, 0x8b,
    0x84, 0x8f, 0xb6, 0xe0, 0x56, 0x9f, 0x21, 0xa1, 0xcf, 0xb2, 0x0f, 0x2c,
    0x93, 0xf8, 0xcf, 0x37, 0xc1, 0x9f, 0x32, 0x98, 0x21, 0x65, 0x52, 0x66,
    0x6e, 0xd3, 0x71, 0x98, 0x55, 0xb9, 0x46, 0x9f, 0x1a, 0x35, 0xc4, 0x47,
    0x69, 0x62, 0x70, 0x4b, 0x77, 0x9e, 0xe4, 0x21, 0xe6, 0x32, 0x5a, 0x26,
    0x05, 0xba, 0x57, 0x53, 0xd7, 0x9b, 0x55, 0x3c, 0xbb, 0x53, 0x79, 0x60,
    0x9c, 0xc8, 0x4d, 0xf7, 0xf5, 0x1d, 0x54, 0x02, 0x91, 0x68, 0x0e, 0xaa,
    0xca, 0x5a, 0x78, 0x0c, 0x28, 0x9a, 0xc3, 0xac, 0x49, 0xc0, 0xf4, 0x85,
    0xee, 0x59, 0x76, 0x7e, 0x28, 0x4e, 0xf1, 0x5c, 0x63, 0xf7, 0xce, 0x0e,
    0x2c, 0x21, 0xa0, 0x58, 0xe9, 0x01, 0xfd, 0xeb, 0xd1, 0xaf, 0xe6, 0xef,
    0x93, 0xb3, 0x95, 0x51, 0x60, 0xa2, 0x74, 0x40, 0x15, 0xe5, 0xf4, 0x0a,
    0xca, 0x6d, 0x9a, 0x37, 0x42, 0x4d, 0x5a, 0x58, 0x49, 0x0f, 0xe9, 0x02,
    0xfc, 0x77, 0xd8, 0x59, 0xde, 0xdd, 0xad, 0x4b, 0x99, 0x2e, 0x64, 0x73,
    0xad, 0x42, 0x2f, 0xf3, 0x2c, 0x0d, 0x49, 0xe4, 0x2e, 0x6c, 0xa4, 0x73,
    0x75, 0x18, 0x14, 0x85, 0xbb, 0x64, 0xb4, 0xa1, 0xb0, 0x6e, 0x01, 0xc0,
    0xcf, 0x17, 0x9c, 0xc5, 0x28, 0xc3, 0x2d, 0x6c, 0x17, 0x2a, 0x3d, 0x06,
    0x5c, 0xf3, 0xb4, 0x49, 0x75, 0xad, 0x17, 0x69, 0xd4, 0xca, 0x65, 0xae,
    0x44, 0x71, 0xa5, 0xf6, 0x0d, 0x0f, 0x8e, 0x37, 0xc7, 0x43, 0xce, 0x6b,
    0x08, 0xe9, 0xd1, 0x34, 0x48, 0x8f, 0xc9, 0xfc, 0xf3, 0x5d, 0x2d, 0xec,
    0x62, 0xd3, 0xf0, 0xb3, 0xfe, 0x2e, 0x40, 0x55, 0x76, 0x54, 0xc7, 0xb4,
    0x61, 0x16, 0xcc, 0x7c, 0x1c, 0x19, 0x24, 0xe6, 0x4d, 0xd4, 0xc3, 0x77,
    0x67, 0x1f, 0x3c, 0x74, 0x79, 0xa1, 0xf8, 0x85, 0x88, 0x1d, 0x6f, 0xa4,
    0x7e, 0x2c, 0x21, 0x9f, 0x49, 0xf5, 0xaa, 0x4e, 0xf3, 0x4a, 0xfa, 0x9d,
    0xbe, 0xf6, 0xce, 0xda, 0xb5, 0xab, 0x39, 0xbd, 0x16, 0x41, 0xa9, 0x4a,
    0xac, 0x09, 0x01, 0xca,
};
static const uint8_t kOutput[] = {
    0x54, 0x30, 0x6a, 0x13, 0xda, 0x59, 0x6b, 0x6d, 0x59, 0x49, 0xc8, 0xc5,
    0xab, 0x26, 0xd4, 0x8a, 0xad, 0xc0, 0x3d, 0xaf, 0x14, 0xb9, 0x15, 0xb8,
    0xca, 0xdf, 0x17, 0xa7, 0x03, 0xd3, 0xc5, 0x06, 0x01, 0xef, 0x21, 0xdd,
    0xa3, 0x0b, 0x9e, 0x48, 0xb8, 0x5e, 0x0b, 0x87, 0x9f, 0x95, 0x23, 0x68,
    0x85, 0x69, 0xd2, 0x5d, 0xaf, 0x57, 0xe9, 0x27, 0x11, 0x3d, 0x49, 0xfa,
    0xf1, 0x08, 0xcc, 0x15, 0xec, 0x1d, 0x19, 0x16, 0x12, 0x9b, 0xc8, 0x66,
    0x1f, 0xfa, 0x2c, 0x93, 0xf4, 0x99, 0x11, 0x27, 0x31, 0x0e, 0xd8, 0x46,
    0x47, 0x40, 0x11, 0x70, 0x01, 0xca, 0xe8, 0x5b, 0xc5, 0x91, 0xc8, 0x3a,
    0xdc, 0xaa, 0xf3, 0x4b, 0x80, 0xe5, 0xbc, 0x03, 0xd0, 0x89, 0x72, 0xbc,
    0xce, 0x2a, 0x76, 0x0c, 0xf5, 0xda, 0x4c, 0x10, 0x06, 0x35, 0x41, 0xb1,
    0xe6, 0xb4, 0xaa, 0x7a, 0xef, 0xf0, 0x62, 0x4a, 0xc5, 0x9f, 0x2c, 0xaf,
    0xb8, 0x2f, 0xd9, 0xd1, 0x01, 0x7a, 0x36, 0x2f, 0x3e, 0x83, 0xa5, 0xeb,
    0x81, 0x70, 0xa0, 0x57, 0x17, 0x46, 0xea, 0x9e, 0xcb, 0x0e, 0x74, 0xd3,
    0x44, 0x57, 0x1d, 0x40, 0x06, 0xf8, 0xb7, 0xcb, 0x5f, 0xf4, 0x79, 0xbd,
    0x11, 0x19, 0xd6, 0xee, 0xf8, 0xb0, 0xaa, 0xdd, 0x00, 0x62, 0xad, 0x3b,
    0x88, 0x9a, 0x88, 0x5b, 0x1b, 0x07, 0xc9, 0xae, 0x9e, 0xa6, 0x94, 0xe5,
    0x55, 0xdb, 0x45, 0x23, 0xb9, 0x2c, 0xcd, 0x29, 0xd3, 0x54, 0xc3, 0x88,
    0x1e, 0x5f, 0x52, 0xf2, 0x09, 0x00, 0x26, 0x26, 0x1a, 0xed, 0xf5, 0xc2,
    0xa9, 0x7d, 0xf9, 0x21, 0x5a, 0xaf, 0x6d, 0xab, 0x8e, 0x16, 0x84, 0x96,
    0xb5, 0x4f, 0xcf, 0x1e, 0xa3, 0xaf, 0x08, 0x9f, 0x79, 0x86, 0xc3, 0xbe,
    0x0c, 0x70, 0xcb, 0x8f, 0xf3, 0xc5, 0xf8, 0xe8, 0x4b, 0x21, 0x7d, 0x18,
    0xa9, 0xed, 0x8b, 0xfb, 0x6b, 0x5a, 0x6f, 0x26, 0x0b, 0x56, 0x04, 0x7c,
    0xfe, 0x0e, 0x1e, 0xc1, 0x3f, 0x82, 0xc5, 0x73, 0xbd, 0x53, 0x0c, 0xf0,
    0xe2, 0xc9, 0xf3, 0x3d, 0x1b, 0x6d, 0xba, 0x70, 0xc1, 0x6d, 0xb6, 0x00,
    0x28, 0xe1, 0xc4, 0x78, 0x62, 0x04, 0xda, 0x23, 0x86, 0xc3, 0xda, 0x74,
    0x3d, 0x7c, 0xd6, 0x76, 0x29, 0xb2, 0x27, 0x2e, 0xb2, 0x35, 0x42, 0x60,
    0x82, 0xcf, 0x30, 0x2c, 0x59, 0xe4, 0xe3, 0xd0, 0x74, 0x1f, 0x58, 0xe8,
    0xda, 0x47, 0x45, 0x73, 0x1c, 0x05, 0x93, 0xae, 0x75, 0xbe, 0x1f, 0x81,
    0xd8, 0xb7, 0xb3, 0xff, 0xfc, 0x8b, 0x52, 0x9e, 0xed, 0x8b, 0x37, 0x9f,
    0xe0, 0xb8, 0xa2, 0x66, 0xe1, 0x6a, 0xc5, 0x1f, 0x1d, 0xf0, 0xde, 0x3f,
    0x3d, 0xb0, 0x28, 0xf3, 0xaa, 0x4e, 0x4d, 0x31, 0xb0, 0x26, 0x79, 0x2b,
    0x08, 0x0f, 0xe9, 0x2f, 0x79, 0xb3, 0xc8, 0xdd, 0xa7, 0x89, 0xa8, 0xa8,
    0x1d, 0x59, 0x0e, 0x4f, 0x1e, 0x93, 0x1f, 0x70, 0x7f, 0x4e, 0x7e, 0xfe,
    0xb8, 0xca, 0x63, 0xe0, 0xa6, 0x05, 0xcc, 0xd7, 0xde, 0x2a, 0x49, 0x31,
    0x78, 0x5c, 0x5f, 0x44, 0xb2, 0x9b, 0x91, 0x99, 0x14, 0x29, 0x63, 0x09,
    0x12, 0xdd, 0x02, 0xd9, 0x7b, 0xe9, 0xf5, 0x12, 0x07, 0xd0, 0xe7, 0xe6,
    0xe8, 0xdd, 0xda, 0xa4, 0x73, 0xc4, 0x8e, 0xbd, 0x7b, 0xb7, 0xbb, 0xcb,
    0x83, 0x2f, 0x43, 0xf6, 0x1c, 0x50, 0xae, 0x9b, 0x2e, 0x52, 0x80, 0x18,
    0x85, 0xa8, 0x23, 0x52, 0x7a, 0x6a, 0xf7, 0x42, 0x36, 0xca, 0x91, 0x5a,
    0x3d, 0x2a, 0xa0, 0x35, 0x7d, 0x70, 0xfc, 0x4c, 0x18, 0x7c, 0x57, 0x72,
    0xcf, 0x9b, 0x29, 0xd6, 0xd0, 0xb4, 0xd7, 0xe6, 0x89, 0x70, 0x69, 0x22,
    0x5e, 0x45, 0x09, 0x4d, 0x49, 0x87, 0x84, 0x5f, 0x8a, 0x5f, 0xe4, 0x15,
    0xd3, 0xe3, 0x72, 0xaf, 0xb2, 0x30, 0x9c, 0xc1, 0xff, 0x8e, 0x6d, 0x2a,
    0x76, 0x9e, 0x08, 0x03, 0x7e, 0xe0, 0xc3, 0xc2, 0x97, 0x06, 0x6b, 0x33,
    0x2b, 0x08, 0xe3, 0xd5, 0x0b, 0xd8, 0x32, 0x67, 0x61, 0x10, 0xed, 0x6b,
    0xed, 0x50, 0xef, 0xd7, 0x1c, 0x1b, 0xe0, 0x6d, 0xa1, 0x64, 0x19, 0x34,
    0x2f, 0xe4, 0xe8, 0x54, 0xbf, 0x84, 0x0e, 0xdf, 0x0e, 0x8b, 0xd8, 0xdd,
    0x77, 0x96, 0xb8, 0x54, 0xab, 0xf2, 0x95, 0x59, 0x0d, 0x0d, 0x0a, 0x15,
    0x6e, 0x01, 0xf2, 0x24, 0xab, 0xa0, 0xd8, 0xdf, 0x38, 0xea, 0x97, 0x58,
    0x76, 0x88, 0xbe, 0xaf, 0x45, 0xe3, 0x56, 0x4f, 0x68, 0xe8, 0x4b, 0xe7,
    0x2b, 0x22, 0x18, 0x96, 0x82, 0x89, 0x25, 0x34, 0xd1, 0xdd, 0x08, 0xea,
    0x7e, 0x21, 0xef, 0x57, 0x55, 0x43, 0xf7, 0xfa, 0xca, 0x1c, 0xde, 0x99,
    0x2e, 0x8b, 0xd8, 0xc3, 0xcf, 0x89, 0x4d, 0xfc, 0x3b, 0x7d, 0x4a, 0xc9,
    0x99, 0xc4, 0x31, 0xb6, 0x7a, 0xae, 0xf8, 0x49, 0xb2, 0x46, 0xc1, 0x60,
    0x05, 0x75, 0xf3, 0x3d, 0xf2, 0xc9, 0x84, 0xa4, 0xb9, 0x8a, 0x87, 0x2a,
    0x87, 0x5c, 0x0a, 0xbc, 0x51, 0x7d, 0x9a, 0xf5, 0xc9, 0x24, 0x2d, 0x5e,
    0xe6, 0xc6, 0xe3, 0xcd, 0x7e, 0xe4, 0xaf, 0x8a, 0x6c, 0x00, 0x04, 0xc8,
    0xd7, 0xa5, 0xad, 0xfa, 0xb2, 0x08, 0x4a, 0x26, 0x9b, 0x7c, 0xd0, 0xc6,
    0x13, 0xb1, 0xb9, 0x65, 0x3f, 0x70, 0x30, 0xf9, 0x98, 0x9d, 0x87, 0x99,
    0x57, 0x71, 0x3e, 0xb1, 0xc3, 0x24, 0xf0, 0xa6, 0xa2, 0x60, 0x9d, 0x66,
    0xd2, 0x5f, 0xae, 0xe3, 0x94, 0x87, 0xea, 0xd1, 0xea, 0x0d, 0x2a, 0x77,
    0xef, 0x31, 0xcc, 0xeb, 0xf9, 0x0c, 0xdc, 0x9c, 0x12, 0x80, 0xbb, 0xb0,
    0x8e, 0xab, 0x9a, 0x04, 0xcd, 0x4b, 0x95, 0x4f, 0x7a, 0x0b, 0x53, 0x7c,
    0x16, 0xcc, 0x0e, 0xb1, 0x73, 0x10, 0xdd, 0xaa, 0x76, 0x94, 0x90, 0xd9,
    0x8b, 0x66, 0x41, 0x31, 0xed, 0x8c, 0x7d, 0x74, 0xc4, 0x33, 0xfa, 0xc3,
    0x43, 0x8d, 0x10, 0xbc, 0x84, 0x4d, 0x0e, 0x95, 0x32, 0xdf, 0x17, 0x43,
    0x6d, 0xd2, 0x5e, 0x12, 0xb9, 0xed, 0x33, 0xd9, 0x97, 0x6f, 0x4a, 0xcd,
    0xc3, 0xcd, 0x81, 0x34, 0xbe, 0x7e, 0xa2, 0xd0, 0xa7, 0x91, 0x5d, 0x90,
    0xf6, 0x5e, 0x4a, 0x25, 0x0f, 0xcc, 0x24, 0xeb, 0xe1, 0xe4, 0x62, 0x6c,
    0x8f, 0x45, 0x36, 0x97, 0x5d, 0xda, 0x20, 0x2b, 0x86, 0x00, 0x8c, 0x94,
    0xa9, 0x6a, 0x69, 0xb2, 0xe9, 0xbb, 0x82, 0x8e, 0x41, 0x95, 0xb4, 0xb7,
    0xf1, 0x55, 0x52, 0x30, 0x39, 0x48, 0xb3, 0x25, 0x82, 0xa9, 0x10, 0x27,
    0x89, 0xb5, 0xe5, 0x1f, 0xab, 0x72, 0x3c, 0x70, 0x08, 0xce, 0xe6, 0x61,
    0xbf, 0x19, 0xc8, 0x90, 0x2b, 0x29, 0x30, 0x3e, 0xb8, 0x4c, 0x33, 0xf0,
    0xf0, 0x15, 0x2e, 0xb7, 0x25, 0xca, 0x99, 0x4b, 0x6f, 0x4b, 0x41, 0x50,
    0xee, 0x56, 0x99, 0xcf, 0x2b, 0xa4, 0xc4, 0x7c, 0x5c, 0xa6, 0xd4, 0x67,
    0x04, 0x5c, 0x5d, 0x5f, 0x26, 0x9e, 0x0f, 0xe2, 0x58, 0x68, 0x4c, 0x30,
    0xcd, 0xef, 0x46, 0xdb, 0x37, 0x6f, 0xbb, 0xc4, 0x80, 0xca, 0x8a, 0x54,
    0x5d, 0x71, 0x9d, 0x0c, 0xe8, 0xb8, 0x2c, 0x10, 0x90, 0x44, 0xa4, 0x88,
    0x3f, 0xbc, 0x15, 0x3c, 0xd2, 0xca, 0x0e, 0xc3, 0xe4, 0x6e, 0xef, 0xb0,
    0xcb, 0xfd, 0x61, 0x7c, 0x27, 0xf2, 0x25, 0xea, 0x71, 0x6d, 0xf7, 0x49,
    0x9c, 0x81, 0x27, 0xf0, 0x61, 0x33, 0xcf, 0x55, 0x68, 0xd3, 0x73, 0xa4,
    0xed, 0x35, 0x65, 0x2a, 0xf2, 0x3e, 0xcf, 0x90, 0x98, 0x54, 0x6d, 0x95,
    0x6a, 0x0c, 0x9c, 0x24, 0x0e, 0xb4, 0xb7, 0x9b, 0x8d, 0x6e, 0x1c, 0xbc,
    0xeb, 0x17, 0x10, 0x86, 0xda, 0x91, 0x6d, 0x89, 0x4c, 0xeb, 0xf5, 0x50,
    0x8f, 0x40, 0xcf, 0x4a,
};

static uint32_t kOverflowCounter = 0xffffffff;

static const uint8_t kOverflowOutput[] = {
    0x37, 0x64, 0x38, 0xcb, 0x25, 0x69, 0x2c, 0xf5, 0x88, 0x8a, 0xfe, 0x6d,
    0x3b, 0x10, 0x07, 0x3c, 0x77, 0xac, 0xcd, 0x1c, 0x0c, 0xa7, 0x17, 0x31,
    0x1d, 0xc3, 0x81, 0xd1, 0xa5, 0x20, 0x55, 0xea, 0xd3, 0x00, 0xc9, 0x84,
    0xde, 0xe2, 0xe5, 0x5e, 0x7b, 0x28, 0x28, 0x59, 0x73, 0x3a, 0x8e, 0x57,
    0x62, 0x18, 0x50, 0x55, 0x97, 0xca, 0x50, 0x3e, 0x8a, 0x84, 0x61, 0x28,
    0x4c, 0x22, 0x93, 0x50, 0x48, 0x7e, 0x65, 0x78, 0x06, 0x5a, 0xcd, 0x2b,
    0x11, 0xf7, 0x10, 0xfd, 0x6f, 0x41, 0x92, 0x82, 0x7c, 0x3a, 0x71, 0x07,
    0x67, 0xd0, 0x7e, 0xb7, 0xdf, 0xdc, 0xfc, 0xee, 0xe6, 0x55, 0xdd, 0x6f,
    0x79, 0x23, 0xf3, 0xae, 0xb1, 0x21, 0x96, 0xbe, 0xea, 0x0e, 0x1b, 0x58,
    0x0b, 0x3f, 0x63, 0x51, 0xd4, 0xce, 0x98, 0xfe, 0x1a, 0xc7, 0xa7, 0x43,
    0x7f, 0x0c, 0xe8, 0x62, 0xcf, 0x78, 0x3f, 0x4e, 0x31, 0xbf, 0x2b, 0x76,
    0x91, 0xcd, 0x19, 0x80, 0x0d, 0x7f, 0x11, 0x8b, 0x76, 0xef, 0x43, 0x3c,
    0x4f, 0x61, 0x86, 0xc5, 0x64, 0xa8, 0xc2, 0x73, 0xc2, 0x64, 0x39, 0xa0,
    0x8b, 0xe6, 0x7f, 0xf6, 0x26, 0xd4, 0x47, 0x4f, 0xe4, 0x46, 0xe2, 0xf5,
    0x9e, 0xe6, 0xc7, 0x76, 0x6c, 0xa9, 0x0f, 0x1d, 0x1b, 0x22, 0xa5, 0x62,
    0x0a, 0x88, 0x3e, 0x8c, 0xf0, 0xbc, 0x4c, 0x11, 0x3f, 0x0d, 0xf7, 0x85,
    0x67, 0x0b, 0x4c, 0xa3, 0x3f, 0xa8, 0xf1, 0x2a, 0x65, 0x2e, 0x00, 0x03,
    0xc9, 0x49, 0x91, 0x48, 0xb7, 0xc8, 0x29, 0x28, 0x2f, 0x46, 0x8e, 0x8b,
    0xd6, 0x73, 0x19, 0x06, 0x3e, 0x6f, 0x92, 0xc8, 0x3d, 0x3f, 0x4d, 0x68,
    0xbc, 0x02, 0xc0, 0x8f, 0x71, 0x46, 0x0d, 0x28, 0x63, 0xfe, 0xad, 0x14,
    0x81, 0x04, 0xb7, 0x23, 0xfd, 0x21, 0x0a, 0xf0, 0x6f, 0xcd, 0x47, 0x0b,
    0x0e, 0x93, 0xa3, 0xa8, 0x44, 0x15, 0xd6, 0xae, 0x06, 0x44, 0x6b, 0xbc,
    0xff, 0x8a, 0x56, 0x60, 0x3c, 0x38, 0xd6, 0xed, 0x03, 0x2d, 0x79, 0x2a,
    0xe9, 0x15, 0xef, 0xfc, 0x92, 0x1f, 0x83, 0xa4, 0x60, 0x8f, 0xc9, 0x29,
    0xb2, 0xb4, 0x9e, 0x3f, 0xa9, 0xe8, 0xfb, 0xa2, 0x62, 0x20, 0x2e, 0xc9,
    0x43, 0xb2, 0xd1, 0x36, 0x85, 0x1e, 0xa4, 0xb3, 0x4f, 0x8c, 0x9e, 0x81,
    0x75, 0x68, 0xbc, 0xf1, 0x52, 0xd5, 0x03, 0x22, 0xcf, 0xdf, 0x64, 0xb0,
    0x28, 0xd2, 0x45, 0x18, 0x38, 0x8c, 0xd0, 0xf6, 0x30, 0x3c, 0x04, 0xd9,
    0x8d, 0xb6, 0xb2, 0x57, 0x2a, 0xee, 0x28, 0xeb, 0x5f, 0x1a, 0x10, 0x6e,
    0x88, 0x79, 0x08, 0x23, 0x19, 0x84, 0xf8, 0x80, 0x1a, 0x7d, 0x6f, 0x8b,
    0xc1, 0x8e, 0x5f, 0x5f, 0x54, 0x14, 0x2a, 0xdc, 0x41, 0x5d, 0xeb, 0x00,
    0xf2, 0x50, 0xae, 0xd3, 0x55, 0x32, 0xf6, 0xd9, 0x34, 0xf4, 0xb2, 0xf2,
    0xf5, 0x90, 0x05, 0x8a, 0x9c, 0xc7, 0x94, 0x5d, 0x2d, 0x5a, 0x0f, 0xdd,
    0x03, 0xde, 0xbe, 0x18, 0xb3, 0xe3, 0x07, 0x6b, 0x57, 0xfa, 0x1b, 0x7b,
    0x75, 0xcb, 0xc2, 0x4d, 0xf7, 0x88, 0xfe, 0xf9, 0xc0, 0x6c, 0xdb, 0x5f,
    0xf6, 0x48, 0x00, 0x4a, 0x5d, 0x75, 0xfa, 0x6b, 0x45, 0x43, 0xc4, 0x7f,
    0x97, 0x31, 0x22, 0xb4, 0x9c, 0xa3, 0xee, 0x2f, 0x27, 0xa9, 0x9f, 0x0e,
    0xdc, 0x40, 0x67, 0x17, 0x2e, 0xcb, 0xfd, 0x9e, 0xe7, 0xb2, 0x85, 0xcd,
    0x49, 0x24, 0xc8, 0x8a, 0x59, 0x6b, 0x1f, 0xec, 0x72, 0x89, 0xf8, 0x30,
    0xdf, 0x82, 0x61, 0x3b, 0x8b, 0xc9, 0x80, 0xe4, 0x27, 0x0d, 0xfe, 0x42,
    0x27, 0x6c, 0xaf, 0x62, 0x3e, 0x2f, 0x1d, 0x38, 0xb6, 0x88, 0x8f, 0x71,
    0x5a, 0x54, 0x6c, 0x68, 0x57, 0x40, 0x49, 0x7a, 0xb2, 0xe8, 0xb6, 0x97,
    0xab, 0xd6, 0x3c, 0x35, 0xf3, 0x95, 0x12, 0xde, 0xa2, 0x39, 0x54, 0x52,
    0x8c, 0x38, 0x2a, 0x2b, 0xe7, 0x21, 0x38, 0x63, 0xb0, 0xd6, 0xad, 0x94,
    0x44, 0xaf, 0x49, 0x5d, 0xfc, 0x49, 0x6b, 0x30, 0xdf, 0xe9, 0x19, 0x1e,
    0xed, 0x98, 0x0d, 0x4a, 0x3d, 0x56, 0x5e, 0x74, 0xad, 0x13, 0x8b, 0x68,
    0x45, 0x08, 0xbe, 0x0e, 0x6c, 0xb4, 0x62, 0x93, 0x27, 0x8b, 0x4f, 0xab,
    0x3e, 0xba, 0xe1, 0xe5, 0xff, 0xa8, 0x5d, 0x33, 0x32, 0xff, 0x34, 0xf9,
    0x8d, 0x67, 0x24, 0x4a, 0xbb, 0x2c, 0x60, 0xb5, 0x88, 0x96, 0x1b, 0xcc,
    0x53, 0xfb, 0x2e, 0x05, 0x1d, 0x8b, 0xc2, 0xa0, 0xde, 0x21, 0x41, 0x5e,
    0x11, 0x1b, 0x96, 0xd9, 0xa6, 0xae, 0xbd, 0xf0, 0x91, 0xad, 0x69, 0x2b,
    0xd2, 0x3f, 0xe4, 0x3d, 0x16, 0x69, 0xa6, 0xb2, 0x9c, 0xbe, 0x59, 0x7b,
    0x87, 0x79, 0xf5, 0xc2, 0x5a, 0xcc, 0xdf, 0xfe, 0x7f, 0xf9, 0xa6, 0x52,
    0xde, 0x5f, 0x46, 0x91, 0x21, 0x2c, 0x2c, 0x49, 0x25, 0x00, 0xd5, 0xe4,
    0x81, 0x6b, 0x85, 0xad, 0x98, 0xaf, 0x06, 0x4a, 0x83, 0xb2, 0xe3, 0x42,
    0x39, 0x31, 0x50, 0xe1, 0x2d, 0x22, 0xe6, 0x07, 0x24, 0x65, 0x29, 0x3f,
    0x4c, 0xbd, 0x14, 0x8d, 0xfa, 0x31, 0xfa, 0xa4, 0xb5, 0x99, 0x04, 0xa2,
    0xa5, 0xcc, 0x3b, 0x12, 0xb1, 0xaa, 0x6a, 0x17, 0x78, 0x8b, 0xb3, 0xe4,
    0x3c, 0x4c, 0xc5, 0xaa, 0x79, 0x12, 0x17, 0xe0, 0x22, 0x4d, 0xf4, 0xa9,
    0xd5, 0xd0, 0xed, 0xf8, 0xfe, 0x0a, 0x45, 0x80, 0x9f, 0x3b, 0x74, 0xa0,
    0xb1, 0xda, 0x18, 0xfa, 0xc2, 0x7d, 0xf6, 0x18, 0x2e, 0xa9, 0x2b, 0x7e,
    0x69, 0x06, 0x43, 0x2d, 0x62, 0x09, 0x42, 0x10, 0x9f, 0x83, 0xad, 0xd9,
    0xdd, 0xcd, 0xcb, 0x1b, 0x33, 0x32, 0x3e, 0x1f, 0xf6, 0xac, 0x3b, 0xa3,
    0x29, 0xd7, 0xc0, 0x88, 0xf9, 0xb7, 0x4c, 0xcd, 0x0a, 0x1f, 0xb8, 0x0f,
    0xe6, 0xf7, 0xd7, 0x4d, 0x5f, 0x06, 0x12, 0x8a, 0x12, 0xa6, 0x2d, 0xbe,
    0x5c, 0x57, 0xf8, 0x7f, 0x54, 0x3f, 0x90, 0x83, 0x2c, 0x0a, 0xc5, 0x3d,
    0x03, 0x78, 0x8a, 0x68, 0xf0, 0xbd, 0xa5, 0x3e, 0xe7, 0x07, 0xab, 0xc8,
    0x58, 0x2f, 0x5c, 0xfd, 0xb5, 0x39, 0xe3, 0xc6, 0x1c, 0x27, 0xf9, 0x0b,
    0xc7, 0x4c, 0xcc, 0x67, 0x62, 0xe6, 0x79, 0xe8, 0xc1, 0x0a, 0x86, 0x8a,
    0xb2, 0x32, 0x7b, 0x90, 0x36, 0x50, 0x92, 0x1f, 0x3e, 0x68, 0x39, 0x1c,
    0x4d, 0x5d, 0xf8, 0x2b, 0xe8, 0x7d, 0xe2, 0x34, 0x61, 0x9e, 0xc3, 0x77,
    0xb9, 0x4c, 0x34, 0x08, 0xda, 0x31, 0xc9, 0x1d, 0xbd, 0x3b, 0x7b, 0xf1,
    0x14, 0xba, 0x3a, 0x34, 0x13, 0xaa, 0x5e, 0xa8, 0x36, 0xf6, 0xfe, 0xed,
    0x5b, 0xef, 0xaf, 0x24, 0x42, 0xba, 0xfc, 0xc9, 0x30, 0x84, 0xec, 0x49,
    0x14, 0xab, 0x58, 0x71, 0xfe, 0x4b, 0x6d, 0x7b, 0x9f, 0xbb, 0x3c, 0x83,
    0xdf, 0x3a, 0xfb, 0x54, 0xff, 0x36, 0xaa, 0x6c, 0x47, 0x94, 0xc0, 0xde,
    0x89, 0x2e, 0xac, 0x68, 0xee, 0xe8, 0xf4, 0xae, 0xa3, 0xe0, 0x91, 0x55,
    0x0b, 0x0c, 0xd7, 0xf4, 0x33, 0xb5, 0xf9, 0xf2, 0x9e, 0xda, 0x78, 0xe5,
    0x75, 0xec, 0xdb, 0xf6, 0xed, 0x27, 0x9f, 0x44, 0x19, 0x9f, 0xb7, 0xf0,
    0xac, 0x1b, 0x3a, 0xf5, 0x77, 0xc7, 0x76, 0x1e, 0x3f, 0x78, 0x12, 0x48,
    0x1d, 0xb8, 0xe0, 0x30, 0x29, 0x9a, 0x8c, 0x8f, 0x21, 0x44, 0x9c, 0x89,
    0xec, 0x8e, 0xd0, 0x81, 0xf5, 0x6a, 0xd0, 0xac, 0x5e, 0xf0, 0x0f, 0x88,
    0x86, 0x31, 0x2e, 0x15, 0x1e, 0x0d, 0x2d, 0xeb, 0x56, 0x30, 0x27, 0x02,
    0x93, 0xf4, 0x07, 0x07, 0xba, 0xf7, 0xbd, 0xe8, 0x27, 0x4f, 0xc6, 0xd9,
    0x57, 0x10, 0x3b, 0xf0, 0xff, 0x2f, 0x2d, 0x6b, 0xd0, 0x17, 0xb3, 0x49,
    0xeb, 0xc2, 0x49, 0xdb,
};


static_assert(sizeof(kInput) == sizeof(kOutput),
              "Input and output lengths don't match.");
static_assert(sizeof(kInput) == sizeof(kOverflowOutput),
              "Input and output lengths don't match.");

TEST(ChaChaTest, TestVector) {
  // Run the test with the test vector at all lengths.
  for (size_t len = 0; len <= sizeof(kInput); len++) {
    SCOPED_TRACE(len);

    std::unique_ptr<uint8_t[]> buf(new uint8_t[len]);
    CRYPTO_chacha_20(buf.get(), kInput, len, kKey, kNonce, kCounter);
    EXPECT_EQ(Bytes(kOutput, len), Bytes(buf.get(), len));

    // Test the in-place version.
    OPENSSL_memcpy(buf.get(), kInput, len);
    CRYPTO_chacha_20(buf.get(), buf.get(), len, kKey, kNonce, kCounter);
    EXPECT_EQ(Bytes(kOutput, len), Bytes(buf.get(), len));
  }
}

TEST(ChaChaTest, CounterOverflow) {
  // Run the test with the test vector at all lengths.
  for (size_t len = 0; len <= sizeof(kInput); len++) {
    SCOPED_TRACE(len);

    std::unique_ptr<uint8_t[]> buf(new uint8_t[len]);
    CRYPTO_chacha_20(buf.get(), kInput, len, kKey, kNonce, kOverflowCounter);
    EXPECT_EQ(Bytes(kOverflowOutput, len), Bytes(buf.get(), len));

    // Test the in-place version.
    OPENSSL_memcpy(buf.get(), kInput, len);
    CRYPTO_chacha_20(buf.get(), buf.get(), len, kKey, kNonce, kOverflowCounter);
    EXPECT_EQ(Bytes(kOverflowOutput, len), Bytes(buf.get(), len));
  }
}

#if defined(CHACHA20_ASM_CTR32) && defined(SUPPORTS_ABI_TEST)
TEST(ChaChaTest, ABI) {
  uint32_t key[8];
  OPENSSL_memcpy(key, kKey, sizeof(key));

  static const uint32_t kCounterNonce[4] = {0};

  std::unique_ptr<uint8_t[]> buf(new uint8_t[sizeof(kInput)]);
  for (size_t len = 0; len <= 32; len++) {
    SCOPED_TRACE(len);
    CHECK_ABI(ChaCha20_ctr32, buf.get(), kInput, len, key, kCounterNonce);
  }

  for (size_t len : {32 * 2, 32 * 4, 32 * 8, 32 * 16, 32 * 24}) {
    SCOPED_TRACE(len);
    CHECK_ABI(ChaCha20_ctr32, buf.get(), kInput, len, key, kCounterNonce);
    // Cover the partial block paths.
    CHECK_ABI(ChaCha20_ctr32, buf.get(), kInput, len + 15, key, kCounterNonce);
  }
}
#endif  // CHACHA20_ASM_CTR32 && SUPPORTS_ABI_TEST

#if defined(CHACHA20_ASM_CTR64) && defined(SUPPORTS_ABI_TEST)
TEST(ChaChaTest, ABI) {
  uint32_t key[8];
  OPENSSL_memcpy(key, kKey, sizeof(key));

  static const uint32_t kCounterNonce[4] = {0};

  std::unique_ptr<uint8_t[]> buf(new uint8_t[sizeof(kInput)]);
  for (size_t len = 0; len <= 32; len++) {
    SCOPED_TRACE(len);
    CHECK_ABI(ChaCha20_ctr64, buf.get(), kInput, len, key, kCounterNonce);
  }

  for (size_t len : {32 * 2, 32 * 4, 32 * 8, 32 * 16, 32 * 24}) {
    SCOPED_TRACE(len);
    CHECK_ABI(ChaCha20_ctr64, buf.get(), kInput, len, key, kCounterNonce);
    // Cover the partial block paths.
    CHECK_ABI(ChaCha20_ctr64, buf.get(), kInput, len + 15, key, kCounterNonce);
  }
}
#endif  // CHACHA20_ASM_CTR64 && SUPPORTS_ABI_TEST
