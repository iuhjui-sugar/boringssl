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

load("@bazel_skylib//lib:selects.bzl", "selects")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")
load(
    ":BUILD.generated.bzl",
    "crypto_headers",
    "crypto_internal_headers",
    "crypto_sources",
    "crypto_sources_apple_aarch64",
    "crypto_sources_apple_arm",
    "crypto_sources_apple_x86",
    "crypto_sources_apple_x86_64",
    "crypto_sources_linux_aarch64",
    "crypto_sources_linux_arm",
    "crypto_sources_linux_ppc64le",
    "crypto_sources_linux_x86",
    "crypto_sources_linux_x86_64",
    "fips_fragments",
    "ssl_headers",
    "ssl_internal_headers",
    "ssl_sources",
    "tool_headers",
    "tool_sources",
)
load(":configs.bzl", "generate_platform_configs", "platform_config_setting")

licenses(["notice"])

exports_files(["LICENSE"])

generate_platform_configs()

posix_copts = [
    # Assembler option --noexecstack adds .note.GNU-stack to each object to
    # ensure that binaries can be built with non-executable stack.
    "-Wa,--noexecstack",

    # This list of warnings should match those in the top-level CMakeLists.txt.
    "-Wall",
    "-Werror",
    "-Wformat=2",
    "-Wsign-compare",
    "-Wmissing-field-initializers",
    "-Wwrite-strings",
    "-Wshadow",
    "-fno-common",
]

glibc_copts = posix_copts + [
    # This is needed on glibc systems (at least) to get rwlock in pthread, but
    # it should not be set on Apple platforms or FreeBSD, where it instead
    # disables APIs we use.
    # See compat(5), sys/cdefs.h, and https://crbug.com/boringssl/471
    "-D_XOPEN_SOURCE=700",
]

boringssl_copts = selects.with_or({
    ":linux_any": glibc_copts,
    (":android_any", ":apple_any"): posix_copts,
    ":windows_any": ["-DWIN32_LEAN_AND_MEAN"],
    "//conditions:default": [],
})

# These selects must be kept in sync.
crypto_sources_asm = select({
    ":linux_ppc": crypto_sources_linux_ppc64le,
    ":linux_armv7": crypto_sources_linux_arm,
    ":linux_arm64": crypto_sources_linux_aarch64,
    ":linux_x86_32": crypto_sources_linux_x86,
    ":linux_x86_64": crypto_sources_linux_x86_64,
    ":android_armv7": crypto_sources_linux_arm,
    ":android_arm64": crypto_sources_linux_aarch64,
    ":android_x86_32": crypto_sources_linux_x86,
    ":android_x86_64": crypto_sources_linux_x86_64,
    ":macos_armv7": crypto_sources_apple_arm,
    ":macos_arm64": crypto_sources_apple_aarch64,
    ":macos_x86_32": crypto_sources_apple_x86,
    ":macos_x86_64": crypto_sources_apple_x86_64,
    ":ios_armv7": crypto_sources_apple_arm,
    ":ios_arm64": crypto_sources_apple_aarch64,
    ":ios_x86_32": crypto_sources_apple_x86,
    ":ios_x86_64": crypto_sources_apple_x86_64,
    ":tvos_armv7": crypto_sources_apple_arm,
    ":tvos_arm64": crypto_sources_apple_aarch64,
    ":tvos_x86_32": crypto_sources_apple_x86,
    ":tvos_x86_64": crypto_sources_apple_x86_64,
    ":watchos_armv7": crypto_sources_apple_arm,
    ":watchos_arm64": crypto_sources_apple_aarch64,
    ":watchos_x86_32": crypto_sources_apple_x86,
    ":watchos_x86_64": crypto_sources_apple_x86_64,
    "//conditions:default": [],
})
boringssl_copts += select({
    ":linux_ppc": [],
    ":linux_armv7": [],
    ":linux_arm64": [],
    ":linux_x86_32": [],
    ":linux_x86_64": [],
    ":android_armv7": [],
    ":android_arm64": [],
    ":android_x86_32": [],
    ":android_x86_64": [],
    ":macos_armv7": [],
    ":macos_arm64": [],
    ":macos_x86_32": [],
    ":macos_x86_64": [],
    ":ios_armv7": [],
    ":ios_arm64": [],
    ":ios_x86_32": [],
    ":ios_x86_64": [],
    ":tvos_armv7": [],
    ":tvos_arm64": [],
    ":tvos_x86_32": [],
    ":tvos_x86_64": [],
    ":watchos_armv7": [],
    ":watchos_arm64": [],
    ":watchos_x86_32": [],
    ":watchos_x86_64": [],
    "//conditions:default": ["-DOPENSSL_NO_ASM"],
})

# For C targets only (not C++), compile with C11 support.
posix_copts_c11 = [
    "-std=c11",
    "-Wmissing-prototypes",
    "-Wold-style-definition",
    "-Wstrict-prototypes",
]

boringssl_copts_c11 = boringssl_copts + selects.with_or({
    (
        ":linux_any",
        ":android_any",
        ":apple_any",
    ): posix_copts_c11,
    "//conditions:default": [],
})

# For C++ targets only (not C), compile with C++14 support.
posix_copts_cxx = [
    "-std=c++14",
    "-Wmissing-declarations",
]

boringssl_copts_cxx = boringssl_copts + selects.with_or({
    (
        ":linux_any",
        ":android_any",
        ":apple_any",
    ): posix_copts_cxx,
    "//conditions:default": [],
})

cc_library(
    name = "crypto",
    srcs = crypto_sources + crypto_internal_headers + crypto_sources_asm,
    hdrs = crypto_headers + fips_fragments,
    copts = boringssl_copts_c11,
    includes = ["src/include"],
    linkopts = select({
        ":windows_any": ["-defaultlib:advapi32.lib"],
        "//conditions:default": ["-pthread"],
    }),
    visibility = ["//visibility:public"],
)

cc_library(
    name = "ssl",
    srcs = ssl_sources + ssl_internal_headers,
    hdrs = ssl_headers,
    copts = boringssl_copts_cxx,
    includes = ["src/include"],
    visibility = ["//visibility:public"],
    deps = [
        ":crypto",
    ],
)

cc_binary(
    name = "bssl",
    srcs = tool_sources + tool_headers,
    copts = boringssl_copts_cxx,
    visibility = ["//visibility:public"],
    deps = [":ssl"],
)
