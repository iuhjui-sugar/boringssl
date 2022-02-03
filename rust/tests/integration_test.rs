// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

//! Basic smoke test to confirm that bssl_sys is joined up to BoringSSL code.

#[test]
fn test_sha256() {
    bssl_sys::init();

    // SHA-256 of a message.
    let msg = [0x00u8];
    let mut tag = [0; bssl_sys::SHA256_DIGEST_LENGTH as usize];
    let result = unsafe {
        // Safety: input pointer is of the specified length, and the output pointer
        // is large enough for the result.
        bssl_sys::SHA256(msg.as_ptr(), msg.len(), tag.as_mut_ptr())
    };
    assert_eq!(result, tag.as_mut_ptr());
    assert_eq!(
        tag,
        [
            0x6eu8, 0x34u8, 0x0bu8, 0x9cu8, 0xffu8, 0xb3u8, 0x7au8, 0x98u8, 0x9cu8, 0xa5u8, 0x44u8,
            0xe6u8, 0xbbu8, 0x78u8, 0x0au8, 0x2cu8, 0x78u8, 0x90u8, 0x1du8, 0x3fu8, 0xb3u8, 0x37u8,
            0x38u8, 0x76u8, 0x85u8, 0x11u8, 0xa3u8, 0x06u8, 0x17u8, 0xafu8, 0xa0u8, 0x1du8
        ]
    );
}

#[test]
fn test_err_get_wrappers() {
    assert_eq!(bssl_sys::ERR_GET_LIB(0x12345678u32), 0x12i32);
    assert_eq!(bssl_sys::ERR_GET_LIB(0xfedcba98u32), 0xfei32);
    assert_eq!(bssl_sys::ERR_GET_REASON(0x12345678u32), 0x0678i32);
    assert_eq!(bssl_sys::ERR_GET_REASON(0xfedcba98u32), 0x0a98i32);

    // If the following test fails, it probably indicates that the compilation
    // of test_wrapper.c has pulled in a system/OpenSSL version of
    //     #include <openssl/err.h>
    // rather than the local BoringSSL version:
    // - OpenSSL (before version 3.0) returns (err >> 12) & 0xFFF.
    // - BoringSSL returns 0 ("BoringSSL errors do not report a function code").
    assert_eq!(bssl_sys::ERR_GET_FUNC(0x12345678u32), 0i32);
    assert_eq!(bssl_sys::ERR_GET_FUNC(0xfedcba98u32), 0i32);
}
