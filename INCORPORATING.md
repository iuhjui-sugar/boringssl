# Incorporating BoringSSL into a project

**Note**: if your target project is not a Google project then first read the [main README](/README.md) about the purpose of BoringSSL.

## Directory layout

Typically projects create a `third_party/boringssl` directory to put BoringSSL-specific files into. The source code of BoringSSL itself goes into `third_party/boringssl/src`, either by copying or as a [submodule](https://git-scm.com/docs/git-submodule).

It's generally a mistake to put BoringSSL's source code into `third_party/boringssl` directly because pre-built files and custom build files need to go somewhere and merging these with the BoringSSL source code makes updating things more complex.

## Build support

BoringSSL is designed to work with many different build systems. Currently, different projects use [gyp](https://gyp.gsrc.io/), [GN](https://chromium.googlesource.com/chromium/src/+/master/tools/gn/docs/quick_start.md), [Bazel](http://bazel.io/) and make to build BoringSSL, without too much pain.

The development build system is CMake and the CMake build knows how to automatically generate the intermediate files that BoringSSL needs. However, outside of the CMake environment, these intermediates are generated once and checked into the incorporating project's source repository. This avoids incorporating projects needing to support Perl and Go in their build systems.

The script [`util/generate_build_files.py`](/util/generate_build_files.py) expects to be run from the `third_party/boringssl` directory and to find the BoringSSL source code in `src/`. You should pass it a single argument: the name of the build system that you're using. If you don't use any of the supported build systems then you should augment `generate_build_files.py` with support for it.

The script will pregenerate the intermediate files (see [BUILDING.md](/BUILDING.md) for details about which tools will need to be installed) and output helper files for that build system. It doesn't generate a complete build script, just file and test lists, which change often. For example, see the [file](https://code.google.com/p/chromium/codesearch#chromium/src/third_party/boringssl/BUILD.generated.gni) and [test](https://code.google.com/p/chromium/codesearch#chromium/src/third_party/boringssl/BUILD.generated_tests.gni) lists generated for GN in Chromium.

## Defines

BoringSSL does not present a lot of configurability in order to reduce the number of configurations that need to be tested. But there are a couple of #defines that you may wish to set:

`OPENSSL_NO_ASM` prevents the use of assembly code (although it's up to you to ensure that the build system doesn't link it in if you wish to reduce binary size). This will have a significant performance impact but can be useful if you wish to use tools like [AddressSanitizer](http://clang.llvm.org/docs/AddressSanitizer.html) that interact poorly with assembly code.

`OPENSSL_SMALL` removes some code that is especially large at some performance cost.

## Symbols

You cannot link multiple versions of BoringSSL/OpenSSL into a single binary without dealing with symbol conflicts. In a static link there's not a lot that can be done because C doesn't have a module system.

When building shared objects (see [BUILDING.md](/BUILDING.md) about defines that you might need to set for this) BoringSSL sets visibility for exposed API and has hidden visibility by default. But once incorporated into a larger code base, you may wish to use a [linker script](https://sourceware.org/binutils/docs/ld/Scripts.html) to hide the BoringSSL symbols. This will prevent any collisions with other versions that may be included in order shared objects.
