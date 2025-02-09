package(default_visibility = ["//visibility:public"])

# Converting the whisper_cpp tarball into a Bazel module
# makes finding include files a bit more complicated.
# This path tends to change with each major version of Bazel
#
EXTERNAL_PATH = "external/+_repo_rules+whisper_cpp"

cc_library(
    name = "whisper",
    srcs = [
        "ggml/src/ggml.c",
        "ggml/src/ggml-alloc.c",
        "ggml/src/ggml-backend.cpp",
        "ggml/src/ggml-backend-impl.h",
        "ggml/src/ggml-impl.h",
        "ggml/src/ggml-quants.c",
        "ggml/src/ggml-backend-reg.cpp",
        "ggml/src/ggml-threading.cpp",
        "ggml/src/ggml-cpu/ggml-cpu.c",
        "ggml/src/ggml-cpu/ggml-cpu-quants.c",
        "ggml/src/ggml-cpu/ggml-cpu.cpp",
        "ggml/src/ggml-cpu/ggml-cpu-traits.cpp",
        "src/whisper.cpp",
    ],
    hdrs = [
        "ggml/include/ggml.h",
        "ggml/include/ggml-cpu.h",
        "ggml/include/ggml-alloc.h",
        "ggml/include/ggml-backend.h",
        "ggml/src/ggml-cpu/ggml-cpu-aarch64.h",
        "ggml/src/ggml-cpu/ggml-cpu-traits.h",
        "ggml/src/ggml-cpu/ggml-cpu-quants.h",
        "ggml/src/ggml-cpu/ggml-cpu-impl.h",
        "ggml/src/ggml-cpu/amx/amx.h",
        "ggml/src/ggml-common.h",
        "ggml/src/ggml-threading.h",
        "ggml/src/ggml-quants.h",
        "include/whisper.h",
    ],
    copts = [
        "-I%s/include" % EXTERNAL_PATH,
        "-I%s/ggml/include" % EXTERNAL_PATH,
        "-I%s/ggml/src" % EXTERNAL_PATH,
        "-I%s/ggml/src/ggml-cpu" % EXTERNAL_PATH,
        "-I%s/ggml-cpu/src" % EXTERNAL_PATH,
        "-pthread",
        "-O3",
        "-ffast-math",
    ],
    defines = [
        "NDEBUG",
        "_XOPEN_SOURCE=600",
        "_GNU_SOURCE",
        "__FINITE_MATH_ONLY__=0",
        "__riscv_v_intrinsic=0",
    ],
)

cc_binary(
    name = "main",
    srcs = [
        "examples/common.cpp",
        "examples/common.h",
        "examples/common-ggml.cpp",
        "examples/common-ggml.h",
        "examples/dr_wav.h",
        "examples/grammar-parser.cpp",
        "examples/grammar-parser.h",
        "examples/cli/cli.cpp",
    ],
    copts = [
        "-I%s/include" % EXTERNAL_PATH,
        "-I%s/ggml/include" % EXTERNAL_PATH,
        "-I%s/ggml/src" % EXTERNAL_PATH,
        "-pthread",
        "-O3",
        "-ffast-math",
    ],
    defines = [
        "NDEBUG",
        "_XOPEN_SOURCE=600",
        "_GNU_SOURCE",
    ],
    includes = [
        "examples",
    ],
    deps = [
        "whisper",
    ],
)
