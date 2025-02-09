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
        "ggml/src/ggml-aarch64.c",
        "ggml/src/ggml-alloc.c",
        "ggml/src/ggml-backend.cpp",
        "ggml/src/ggml-backend-impl.h",
        "ggml/src/ggml-impl.h",
        "ggml/src/ggml-quants.c",
        "src/whisper.cpp",
    ],
    hdrs = [
        "ggml/include/ggml.h",
        "ggml/include/ggml-alloc.h",
        "ggml/include/ggml-backend.h",
        "ggml/src/ggml-aarch64.h",
        "ggml/src/ggml-common.h",
        "ggml/src/ggml-cpu-impl.h",
        "ggml/src/ggml-quants.h",
        "include/whisper.h",
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
        "examples/main/main.cpp",
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
