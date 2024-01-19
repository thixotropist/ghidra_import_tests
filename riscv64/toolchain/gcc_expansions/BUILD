#
# Compile gcc testsuite files to demonstrate common expansions for utility operations
# like memory copy, structure copy, string ops, and bit ops.
# build with bazel build --platforms=//platforms:riscv_vector gcc_expansions:vector_vl512
#

filegroup(
    name = 'sources',
    srcs = [
        'cpymem.c',
        'setmem.c',
        'string.c',
    ]
)

# generic 64 bit RISCV processor
cc_library (
    name = 'gcc_expansions_baseline',
    srcs = [':sources'],
    copts = ['-O2', '-march=rv64gc'],
    linkstatic = False,
)

# vector-capable 64 bit RISCV processors with arbitrary vector lengths
cc_library (
    name = 'gcc_expansions_vector',
    srcs = [':sources'],
    copts = ['-O2', '-march=rv64gcv'],
)

# 512 bit vector length, e.g. SiFive X390 for AI and ML apps
cc_library (
    name = 'gcc_expansions_vector_vl512',
    srcs = [':sources'],
    copts = ['-O2', '-march=rv64gcv_zvl512b'],
)

# 128 bit vector length, e.g. SiFive P870 for data centers
cc_library (
    name = 'gcc_expansions_vector_vl128',
    srcs = [':sources'],
    copts = ['-O2', '-march=rv64gcv_zvl128b'],
)

# 1024 bit vector length
cc_library (
    name = 'gcc_expansions_vector_vl1024',
    srcs = [':sources'],
    copts = ['-O2', '-march=rv64gcv_zvl1024b'],
)
# T-Head bit manipulation extensions
cc_library (
    name = 'gcc_expansions_rv64gc_xtheadbb',
    srcs = [':sources'],
    copts = [
        '-O2',
        '-minline-strcmp',
        '-minline-strncmp',
        '-march=rv64gc_xtheadbb',
    ],
)

genrule(
    name = 'archive',
    srcs = [
        ':sources',
        ':gcc_expansions_baseline',
        ':gcc_expansions_vector',
        ':gcc_expansions_vector_vl128',
        ':gcc_expansions_vector_vl512',
        ':gcc_expansions_vector_vl1024',
        ':gcc_expansions_rv64gc_xtheadbb',
    ],
    outs = ["archive.tar"],
    cmd = 
        """
        tar cJhf $(location archive.tar) $(locations :sources) $(locations :gcc_expansions_baseline) $(locations :gcc_expansions_vector) $(locations :gcc_expansions_vector_vl128) \
         $(locations :gcc_expansions_vector_vl512) $(locations :gcc_expansions_vector_vl1024) $(locations :gcc_expansions_rv64gc_xtheadbb)
        """
)