"""Useful macros for device/platform compatibility."""

load("@bazel_skylib//lib:selects.bzl", "selects")

def platform_config_setting(
        name,
        flag_values = {},
        platform_constraints = []):
    cpu_config = "_cpu_%s" % name
    platform_config = "_platform_%s" % name
    selects.config_setting_group(
        name = name,
        match_any = [
            ":%s" % cpu_config,
            ":%s" % platform_config,
        ],
    )

    native.config_setting(
        name = cpu_config,
        values = flag_values,
        visibility = ["//visibility:private"],
    )

    native.config_setting(
        name = platform_config,
        constraint_values = platform_constraints,
        visibility = ["//visibility:private"],
    )

OS = ["linux", "android", "macos", "ios", "tvos", "watchos", "windows"]

# Platform data to generate legacy and new-style config settings.
_CpuInfo = provider(fields = ["flag", "constraint"])

_PlatformInfo = provider(fields = ["os", "cpus", "crosstool_top"])

PLATFORMS = [
    _PlatformInfo(
        os = "linux",
        cpus = [
            _CpuInfo(flag = "k8", constraint = "x86_64"),
            _CpuInfo(flag = "piii", constraint = "x86_32"),
            _CpuInfo(flag = "ppc", constraint = "ppc"),
            _CpuInfo(flag = "arm", constraint = "armv7"),
            _CpuInfo(flag = "arm64", constraint = "arm64"),
        ],
    ),
    _PlatformInfo(
        os = "macos",
        cpus = [
            _CpuInfo(flag = "darwin_x86_64", constraint = "x86_64"),
            _CpuInfo(flag = "darwin_x86_32", constraint = "x86_32"),
            _CpuInfo(flag = "darwin_arm64", constraint = "arm64"),
            _CpuInfo(flag = "darwin_armv7", constraint = "armv7"),
        ],
    ),
    _PlatformInfo(
        os = "ios",
        cpus = [
            _CpuInfo(flag = "ios_x86_64", constraint = "x86_64"),
            _CpuInfo(flag = "ios_x86_32", constraint = "x86_32"),
            _CpuInfo(flag = "ios_arm64", constraint = "arm64"),
            _CpuInfo(flag = "ios_armv7", constraint = "armv7"),
        ],
    ),
    _PlatformInfo(
        os = "tvos",
        cpus = [
            _CpuInfo(flag = "tvos_x86_64", constraint = "x86_64"),
            _CpuInfo(flag = "tvos_x86_32", constraint = "x86_32"),
            _CpuInfo(flag = "tvos_arm64", constraint = "arm64"),
            _CpuInfo(flag = "tvos_armv7", constraint = "armv7"),
        ],
    ),
    _PlatformInfo(
        os = "watchos",
        cpus = [
            _CpuInfo(flag = "watchos_x86_64", constraint = "x86_64"),
            _CpuInfo(flag = "watchos_x86_32", constraint = "x86_32"),
            _CpuInfo(flag = "watchos_arm64", constraint = "arm64"),
            _CpuInfo(flag = "watchos_armv7", constraint = "armv7"),
        ],
    ),
    _PlatformInfo(
        os = "windows",
        cpus = [
            _CpuInfo(flag = "windows_x86_64", constraint = "x86_64"),
        ],
    ),
    _PlatformInfo(
        os = "android",
        crosstool_top = "@androidndk//:toolchain",
        cpus = [
            _CpuInfo(flag = "x86_64", constraint = "x86_64"),
            _CpuInfo(flag = "x86", constraint = "x86_32"),
            _CpuInfo(flag = "arm64-v8a", constraint = "arm64"),
            _CpuInfo(flag = "armeabi-v7a", constraint = "armv7"),
        ],
    ),
]

def generate_platform_configs():
    for platform in PLATFORMS:
        names = []
        for cpu in platform.cpus:
            name = "%s_%s" % (platform.os, cpu.flag)
            names.append(name)
            flag_values = {"cpu": cpu.flag}
            if hasattr(platform, "crosstool_top"):
                flag_values["crosstool_top"] = platform.crosstool_top
            platform_config_setting(
                name = name,
                flag_values = flag_values,
                platform_constraints = [
                    "@platforms//os:%s" % platform.os,
                    "@platforms//cpu:%s" % cpu.constraint,
                ],
            )

        # Now write the master config
        selects.config_setting_group(
            name = "%s_any" % platform.os,
            match_any = [":%s" % name for name in names],
        )

    # All Applish platforms.
    selects.config_setting_group(
        name = "apple_any",
        match_any = [
            ":macos_any",
            ":ios_any",
            ":tvos_any",
            ":watchos_any",
        ],
    )
