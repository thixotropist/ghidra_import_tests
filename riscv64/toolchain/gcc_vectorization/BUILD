# Use the development snapshot of gcc14 to compile sample programs
# using riscv vector intrinsics.  Note that gcc14 will in some cases autovectorize the
# 'golden' C code too, letting us compare manually vectorized with autovectorized loops.

[
    cc_binary(
        name = file,
        srcs = [
            "common.h",
            file + ".c",
        ],
        copts = [
            "-O3",
            "-march=rv64gcv",
        ],
    )
    for file in (
        "rvv_index",
        "rvv_matmul",
        "rvv_memcpy",
        "rvv_reduce",
        "rvv_strncpy",
        "helloworld_challenge",
    )
]
