# Copyright (c) 2024, Google Inc.
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
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

load("@rules_cc//cc:defs.bzl", "cc_library")

def bssl_cc_library(
        name,
        srcs = [],
        asm_srcs = [],
        hdrs = [],
        internal_hdrs = [],
        copts = [],
        includes = [],
        linkopts = [],
        deps = [],
        testonly = False,
        exported = False):
    # By default, the C files will expect assembly files, if any, to be linked
    # in with the build. This default can be flipped with -DOPENSSL_NO_ASM. If
    # building in a configuration where we have no assembly optimizations,
    # -DOPENSSL_NO_ASM has no effect, and either value is fine.
    #
    # Like C files, assembly files are wrapped in #ifdef (or NASM equivalent),
    # so it is safe to include a file for the wrong platform in the build. It
    # will just output an empty object file. However, we need some platform
    # selectors to distinguish between gas or NASM syntax.
    #
    # For all non-Windows platforms, we use gas assembly syntax and can assume
    # any GCC-compatible toolchain includes a gas-compatible assembler.
    #
    # For Windows, we use NASM on x86 and x86_64 and gas, specifically
    # clang-assembler, on aarch64. We have not yet added NASM support to this
    # build, and would need to detect MSVC vs clang-cl for aarch64 so, for now,
    # we just disable assembly on Windows across the board.
    #
    # These selects for asm_srcs_used and asm_copts must be kept in sync. If we
    # specify assembly, we don't want OPENSSL_NO_ASM. If we don't specify
    # assembly, we want OPENSSL_NO_ASM, in case the C files expect them in some
    # format (e.g. NASM) this build file doesn't yet support.
    #
    # TODO(https://crbug.com/boringssl/531): Enable assembly for Windows.
    asm_srcs_used = select({
        "@platforms//os:windows": [],
        "//conditions:default": asm_srcs,
    })
    asm_copts = select({
        "@platforms//os:windows": ["-DOPENSSL_NO_ASM"],
        "//conditions:default": [],
    })

    # BoringSSL's notion of internal headers are slightly different from
    # Bazel's. libcrypto's internal headers may be used by libssl, but they
    # cannot be used outside the library. To express this, we make separate
    # internal and external targets. This impact's Bazel's layering check.
    name_internal = name
    if exported:
        name_internal = name + "_internal"
    cc_library(
        name = name_internal,
        srcs = srcs + asm_srcs_used,
        hdrs = hdrs + internal_hdrs,
        copts = copts + asm_copts,
        includes = includes,
        linkopts = linkopts,
        deps = deps,
        testonly = testonly,
    )

    if exported:
        cc_library(
            name = name,
            hdrs = hdrs,
            deps = [":" + name_internal],
            visibility = ["//visibility:public"]
        )
