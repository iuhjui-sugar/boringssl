# Copyright (c) 2016, Google Inc.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

# This file is moved to the top-level of the repository in the *-with-bazel
# branches. See INCORPORATING.md.

licenses(["notice"])

exports_files(["LICENSE"])

load(
    ":BUILD.generated.bzl",
    "crypto_headers",
    "crypto_internal_headers",
    "crypto_sources",
    "crypto_sources_linux_aarch64",
    "crypto_sources_linux_arm",
    "crypto_sources_linux_x86",
    "crypto_sources_linux_x86_64",
    "crypto_sources_mac_x86_64",
    "crypto_sources_win_x86_64",
    "ssl_headers",
    "ssl_internal_headers",
    "ssl_sources",
    "tool_sources",
    "tool_headers",
)

config_setting(
    name = "k8",
    values = {"cpu": "k8"},
)

config_setting(
    name = "darwin",
    values = {"cpu": "darwin"},
)

boringssl_copts = [
    "-Isrc/include",

    # Assembler option --noexecstack adds .note.GNU-stack to each object to
    # ensure that binaries can be built with non-executable stack.
    "-Wa,--noexecstack",

    # This is needed on Linux systems (at least) to get rwlock in pthread.
    "-D_XOPEN_SOURCE=700",

    # Modern build environments should be able to set this to use atomic
    # operations for reference counting rather than locks. However, it's
    # known not to work on some Android builds.
    # "-DOPENSSL_C11_ATOMIC",
] + select({
    ":k8": [],
    ":darwin": [],
    "//conditions:default": ["-DOPENSSL_NO_ASM"],
})

crypto_sources_asm = select({
    ":k8": crypto_sources_linux_x86_64,
    ":darwin": crypto_sources_mac_x86_64,
    "//conditions:default": [],
})

# For C targets only (not C++), compile with C11 support.
boringssl_copts_c11 = boringssl_copts + ["-std=c11"]

cc_library(
    name = "crypto",
    srcs = crypto_sources + crypto_internal_headers + crypto_sources_asm,
    hdrs = crypto_headers,
    copts = boringssl_copts_c11,
    includes = ["src/include"],
    linkopts = select({
        ":darwin": [],
        "//conditions:default": ["-lpthread"],
    }),
    visibility = ["//visibility:public"],
)

cc_library(
    name = "ssl",
    srcs = ssl_internal_headers + crypto_internal_headers + ssl_sources,
    hdrs = ssl_headers,
    copts = boringssl_copts_c11,
    includes = ["src/include"],
    visibility = ["//visibility:public"],
    deps = [":crypto"],
)

cc_binary(
    name = "bssl",
    srcs = tool_sources + tool_headers + [
        "src/crypto/test/scoped_types.h",
        "src/ssl/test/scoped_types.h",
    ],
    visibility = ["//visibility:public"],
    deps = [":ssl"],
)
