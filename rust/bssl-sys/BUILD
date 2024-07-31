load("@rules_rust//bindgen:defs.bzl", "rust_bindgen_library")

rust_bindgen_library(
    name = "bssl-sys",
    bindgen_flags = [
        "--no-derive-default",
        "--enable-function-attribute-detection",
        "--use-core",
        "--default-macro-constant-type=signed",
        "--rustified-enum=point_conversion_form_t",
        "--allowlist-file=.*[[:punct:]]openssl[[:punct:]].*\\.h",
    ],
    wrap_static_fns = True,
    cc_lib = ":wrapper",
    header = "wrapper.h",
    visibility = [
        "//rust:__subpackages__",
    ],
)

cc_library(
    name = "wrapper",
    srcs = [
        "rust_wrapper.c",
        "rust_wrapper.h",
    ],
    hdrs = ["wrapper.h"],
    deps = [
        "//:crypto",
        "//:ssl",
    ],
)