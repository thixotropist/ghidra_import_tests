# Use the development snapshot of gcc14 to compile sample programs
# using riscv vector intrinsics.  Note that gcc14 will in some cases autovectorize the
# 'golden' C code too, letting us compare manually vectorized with autovectorized loops.


# nested list comprehensions give us rules for all combinations of source code and machine architecture
[
    [
        cc_binary(
            name = file + "_" + march,
            srcs = [
                "common.h",
                file + ".c",
            ],
            copts = [
                "-O3",
                "-march=" + march,
            ],
        )
        for file in (
            "memcpy",
            "narrowing_loop",
            "index",
        )
    ]
    for march in (
        "x86-64-v2",
        "x86-64-v3",
        "x86-64-v4",
    )
]

OBJDUMP = "/opt/gcc14/bin/objdump"

[   genrule(
    name = file + "-refdump",
    srcs = [file],
    outs = [file + ".objdump"],
    cmd = OBJDUMP + " -d $(location {}) > $(location {}.objdump)".format(file, file)
    )
    for file in (
        "memcpy_x86-64-v2",
        "memcpy_x86-64-v3",
        "memcpy_x86-64-v4",
        "narrowing_loop_x86-64-v2",
        "narrowing_loop_x86-64-v3",
        "narrowing_loop_x86-64-v4",
        "index_x86-64-v2",
        "index_x86-64-v3",
        "index_x86-64-v4",
    )
]


filegroup(
    name = "exemplars",
    srcs = [
        "memcpy.c",
        ":memcpy_x86-64-v2",
        ":memcpy_x86-64-v2-refdump",
        ":memcpy_x86-64-v3",
        ":memcpy_x86-64-v3-refdump",
        ":memcpy_x86-64-v4",
        ":memcpy_x86-64-v4-refdump",
        "narrowing_loop.c",
        ":narrowing_loop_x86-64-v2",
        ":narrowing_loop_x86-64-v2-refdump",
        ":narrowing_loop_x86-64-v3",
        ":narrowing_loop_x86-64-v3-refdump",
        ":narrowing_loop_x86-64-v4",
        ":narrowing_loop_x86-64-v4-refdump",
        "index.c",
        ":index_x86-64-v2",
        ":index_x86-64-v2-refdump",
        ":index_x86-64-v3",
        ":index_x86-64-v3-refdump",
        ":index_x86-64-v4",
        ":index_x86-64-v4-refdump",
    ]
)

genrule(
    name = "archive",
    srcs = [
        ":exemplars",
    ],
    outs = ["archive.tar"],
    cmd = 
        """
        tar cJhf $(location archive.tar) $(locations :exemplars)
        """
)
