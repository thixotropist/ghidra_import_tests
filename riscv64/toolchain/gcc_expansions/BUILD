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
    name = 'baseline',
    srcs = [':sources'],
    copts = ['-O2', '-march=rv64gc'],
    linkstatic = False,
)

# vector-capable 64 bit RISCV processors with arbitrary vector lengths
cc_library (
    name = 'vector',
    srcs = [':sources'],
    copts = ['-O2', '-march=rv64gcv'],
)

# 512 bit vector length, e.g. SiFive X390 for AI and ML apps
cc_library (
    name = 'vector_vl512',
    srcs = [':sources'],
    copts = ['-O2', '-march=rv64gcv_zvl512b'],
)

# 128 bit vector length, e.g. SiFive P870 for data centers
cc_library (
    name = 'vector_vl128',
    srcs = [':sources'],
    copts = ['-O2', '-march=rv64gcv_zvl128b'],
)

# 1024 bit vector length
cc_library (
    name = 'vector_vl1024',
    srcs = [':sources'],
    copts = ['-O2', '-march=rv64gcv_zvl1024b'],
)
# T-Head bit manipulation extensions
cc_library (
    name = 'rv64gc_xtheadbb',
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
        ':baseline',
        ':vector',
        ':vector_vl128',
        ':vector_vl512',
        ':vector_vl1024',
        ':rv64gc_xtheadbb',
    ],
    outs = ["archive.tar"],
    cmd = 
        """
        tar cJhf  $(location archive.tar) $(locations :sources) $(locations :baseline) $(locations :vector) $(locations :vector_vl128) \
         $(locations :vector_vl512) $(locations :vector_vl1024) $(locations :rv64gc_xtheadbb)
        """
)