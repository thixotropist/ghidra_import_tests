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
#            "-march=alderlake",
#            "-march=raptorlake",
#            "-march=sapphirerapids",
#            "-march=rocketlake",
        ],
    )
    for file in (
        "rvv_index",
        "rvv_matmul",
        "memcpy",
        "rvv_reduce",
        "rvv_strncpy",
        "helloworld_challenge",
        "narrowing_loop",
    )
]

[
    cc_binary(
        name = "memcpy_" + march,
        srcs = [
            "common.h",
            "memcpy_demo.c",
        ],
        copts = [
            "-O3",
            "-march=" + march,
            ]
    )
    for march in (
        "alderlake",
        "raptorlake",
        "rocketlake",
        "sapphirerapids"
    )
]
