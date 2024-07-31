load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

rust_library(
    name = "bssl-crypto",
    srcs = glob(include = ["src/**/*.rs"]),
    deps = [
        "//rust/bssl-sys:bssl-sys",
    ],
    visibility = ["//visibility:public"],
)

rust_test(
    name = "bssl-crypto_test",
    crate = ":bssl-crypto",
)