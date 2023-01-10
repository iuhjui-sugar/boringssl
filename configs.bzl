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

# Dictionary of platform data.
# Keys are OS. Values are --cpu flag to @platforms//cpu mapping.
PLATFORMS = {
    "linux": {
        "k8": "x86_64",
        "piii": "x86_32",
        "ppc": "ppc",
        "arm": "armv7",
        "arm64": "arm64",
    },
    "macos": {
        "darwin_x86_64": "x86_64",
        "darwin_x86_32": "x86_32",
        "darwin_arm64": "arm64",
        "darwin_armv7": "armv7",
    },
    "ios": {
        "ios_x86_64": "x86_64",
        "ios_x86_32": "x86_32",
        "ios_arm64": "arm64",
        "ios_armv7": "armv7",
    },
    "tvos": {
        "tvos_x86_64": "x86_64",
        "tvos_x86_32": "x86_32",
        "tvos_arm64": "arm64",
        "tvos_armv7": "armv7",
    },
    "watchos": {
        "watchos_x86_64": "x86_64",
        "watchos_x86_32": "x86_32",
        "watchos_arm64": "arm64",
        "watchos_armv7": "armv7",
    },
    "windows": {
        "windows_x86_64": "x86_64",
    },
    "android": {
        "x86_64": "x86_64",
        "x86": "x86_32",
        "arm64-v8a": "arm64",
        "armeabi-v7a": "armv7",
    },
}

def generate_platform_configs():
    for os, data in PLATFORMS.items():
        names = []
        for cpu_flag, constraint_name in data.items():
            name = "%s_%s" % (os, constraint_name)
            names.append(name)
            platform_config_setting(
                name = name,
                flag_values = {"cpu": cpu_flag},
                platform_constraints = [
                    "@platforms//os:%s" % os,
                    "@platforms//cpu:%s" % constraint_name,
                ],
            )

        # Now write the master config
        selects.config_setting_group(
            name = "%s_any" % os,
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
