# Use the development snapshot of gcc14 to compile sample programs
# using riscv vector intrinsics.

[
    cc_binary(
        name = file + "_vector",
        srcs = [
            "common.h",
            file + ".c",
        ],
        copts = [
            "-march=rv64gcv",
        ],
    )
    for file in (
        "rvv_index",
        "rvv_matmul",
        "rvv_memcpy",
        "rvv_reduce",
        "rvv_strncpy",
        "narrowing_loop",
        "memcpy",
    )
]

[
    cc_binary(
        name = file,
        srcs = [
            "common.h",
            file + ".c",
        ],
        copts = [
            "-march=rv64gc",
        ],
    )
    for file in (
        "narrowing_loop",
        "memcpy",
    )
]

[
    cc_binary(
        name = file + "_lto",
        srcs = [
            "common.h",
            file + ".c",
        ],
        copts = [
            "-O3",
            "-march=rv64gcv",
            "-flto",
        ],
        linkopts = [
            "-Wl,-flto",
        ],
    )
    for file in (
        "narrowing_loop",
        "memcpy",
    )
]

cc_library(
    name = "autovec_binop",
    srcs = [
        "vadd-rv64gcv.c",
        "vadd-template.h",
        "vmax-rv64gcv.c",
        "vmax-template.h",
        "vmul-rv64gcv.c",
        "vmul-template.h",
    ],
    copts = [
        "-O3",
        "-march=rv64gcv",
        "-ffast-math",
    ],
)
