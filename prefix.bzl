# Copyright (c) 2021, Google Inc.
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

SymbolPrefixInfo = provider(fields = ["prefix"])

def _symbol_prefix_impl(ctx):
    return SymbolPrefixInfo(prefix = ctx.build_setting_value)

symbol_prefix = rule(
    implementation = _symbol_prefix_impl,
    build_setting = config.string(),
)

def _transition_symbol_prefix_impl(settings, attr):
    return {"@boringssl//:boringssl_prefix": attr.symbol_prefix}

transition_symbol_prefix = transition(
    implementation = _transition_symbol_prefix_impl,
    inputs = [],
    outputs = ["@boringssl//:boringssl_prefix"],
)

def _generate_symbol_list_impl(ctx):
    symlist = ctx.actions.declare_file("{}.txt".format(ctx.label.name))
    srcs = [src for src in ctx.files.srcs if src.extension == "a"]
    ctx.actions.run(
        outputs = [symlist],
        inputs = srcs + ctx.files._tool,
        arguments = [
            "-out",
            symlist.path,
        ] + [src.path for src in srcs],
        executable = ctx.files._tool[0],
    )
    return [DefaultInfo(files = depset([symlist]))]

generate_symbol_list = rule(
    implementation = _generate_symbol_list_impl,
    attrs = {
        "srcs": attr.label_list(),
        "_tool": attr.label(default = "//src/util:read_symbols", allow_files = True),
    },
)

def _make_prefix_headers_impl(ctx):
    prefix = ctx.attr._prefix[SymbolPrefixInfo].prefix
    if prefix == "":
        return [CcInfo()]

    hdr = ctx.actions.declare_file("{}/boringssl_prefix_symbols.h".format(ctx.attr.dir))
    asmhdr = ctx.actions.declare_file("{}/boringssl_prefix_symbols_asm.h".format(ctx.attr.dir))
    inchdr = ctx.actions.declare_file("{}/boringssl_prefix_symbols_nasm.inc".format(ctx.attr.dir))

    ctx.actions.run(
        outputs = [hdr, asmhdr, inchdr],
        inputs = ctx.files.symbols + ctx.files._tool,
        arguments = [
            "-out",
            hdr.dirname,
        ] + [s.path for s in ctx.files.symbols],
        executable = ctx.files._tool[0],
    )

    return [
        CcInfo(compilation_context = cc_common.create_compilation_context(
            defines = depset(["BORINGSSL_PREFIX={}".format(prefix)]),
            includes = depset([hdr.dirname]),
            headers = depset([hdr, asmhdr, inchdr]),
        )),
        DefaultInfo(files = depset([hdr, asmhdr, inchdr])),
    ]

make_prefix_headers = rule(
    implementation = _make_prefix_headers_impl,
    attrs = {
        "dir": attr.string(default = "src/include/openssl"),
        "symbols": attr.label(allow_files = True),
        "_prefix": attr.label(default = "//:boringssl_prefix"),
        "_tool": attr.label(default = "//src/util:make_prefix_headers", allow_files = True),
    },
)

def _boringssl_prefixed_library_impl(ctx):
    return [
        ctx.attr.library[0][DefaultInfo],
        ctx.attr.library[0][CcInfo],
    ]

boringssl_prefixed_library = rule(
    implementation = _boringssl_prefixed_library_impl,
    attrs = {
        "library": attr.label(providers = [CcInfo], cfg = transition_symbol_prefix),
        "symbol_prefix": attr.string(),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)
