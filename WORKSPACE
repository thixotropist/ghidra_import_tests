load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# gcc-14 risc-v 64 bit compiler suite, with C and C++ but no lto support
http_archive(
    name = "gcc-14-riscv64-suite",
    urls = ["file:///opt/bazel/risc64_linux_gnu-14.tar.xz"],
    build_file = "//:gcc-14-riscv64-suite.BUILD",
    sha256 = "045d3ac375008a97330ca8ab19605bc38ec0479cf9778cc28924eefa07b7a07b",
)

# gcc-14 x86-64 bit compiler suite
http_archive(
    name = "gcc-14-x86_64-suite",
    urls = ["file:///opt/bazel/x86_64_linux_gnu-14.tar.xz"],
    build_file = "//:gcc-14-x86_64-suite.BUILD",
    sha256 = "3c5486f025153c73e0256550eae3d2e147c0607acffcbedb989fddc7bd4e0956",
)

# system libraries used by compiler suite executables
# We built the custom toolchain on a fedora x86_64 platform, so we need some
# fedora x86_64 sharable system libraries to execute.
http_archive(
    name = "fedora40-system-libs",
    urls = ["file:///opt/bazel/fedora40_system_libs.tar.xz"],
    build_file = "//:fedora40-system-libs.BUILD",
    sha256 = "ff417a1d466aee59cdb3792be2cc78a6405857697414ec5da97728b5a0a3832c",
)

# whisper.cpp is an open source voice-to-text inference app built on Meta's LLaMA model.
# It is a useful exemplar of autovectorization of ML code with some examples of hand-coded
# riscv intrinsics.
http_archive(
    name = "whisper_cpp",
    urls = ["https://github.com/ggerganov/whisper.cpp/archive/refs/tags/v1.5.4.tar.gz"],
    strip_prefix = "whisper.cpp-1.5.4/",
    build_file = "//:whisper-cpp.BUILD",
    sha256 = "06eed84de310fdf5408527e41e863ac3b80b8603576ba0521177464b1b341a3a"
)

register_toolchains(
    # a separate Bazel project independent of /opt/riscv,
    # currently based on gcc-14-riscv64-suite
    "//riscv64/generated/toolchains:riscv64-default",
    # a toolchain based on a snapshot of gcc-14-riscv64-suite
    "//riscv64/generated/toolchains:riscv64-next",
    # a toolchain loaded with supported customizations
    "//riscv64/generated/toolchains:riscv64-custom",
    # a non-hermetic local toolchain used in debugging the Bazel sandbox
    "//riscv64/generated/toolchains:riscv64-local",
    # an x86_64 toolchain for unit testing, hopefully aligned with riscv64-next
    "//riscv64/generated/toolchains:x86_64-next",
    # a generic x86_64 toolchain
    "//x86_64/generated/toolchains:x86_64_default",
)
