package(default_visibility = ["//visibility:public"])

cc_library(
    name = 'whisper',
    hdrs = [
        'ggml.h',
        'ggml-common.h',
        'ggml-quants.h',
        'whisper.h',
        'ggml-backend.h',
    ],
    srcs = [
        'ggml-impl.h',
        'ggml-backend-impl.h',
        'ggml-alloc.h',
        'ggml.c',
        'ggml-alloc.c',
        'ggml-backend.c',
        'ggml-quants.c',
        'whisper.cpp',
    ],
    defines = [
        'NDEBUG',
        '_XOPEN_SOURCE=600',
        '_GNU_SOURCE',
    ],
    copts = [
        '-pthread',
         '-O3',
         "-ffast-math",
    ]
)

cc_binary(
    name = 'main',
    srcs = [
        'examples/common.h',
        'examples/dr_wav.h',
        'examples/grammar-parser.h',
        'examples/grammar-parser.cpp',
        'examples/main/main.cpp',
        'examples/common.cpp',
        'examples/common-ggml.h',
        'examples/common-ggml.cpp',
    ],
    deps = [
        'whisper'
    ],
    includes = [
        'examples',
    ],
    defines = [
        'NDEBUG',
        '_XOPEN_SOURCE=600',
        '_GNU_SOURCE',
        '__riscv_v_intrinsic'
    ],
    copts = [
        '-pthread',
        '-O3',
        "-ffast-math"
    ]
)
