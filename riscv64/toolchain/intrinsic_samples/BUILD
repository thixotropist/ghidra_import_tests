
# Use the development snapshot of gcc14 to compile sample programs
# using riscv vector instrinsics. The initial gcc14 toolchain does not include
# everything needed for library creation, so we will see errors after the
# compilation to object files.
cc_library(
    name = "exemplars",
    srcs = [
        "common.h",
        "rvv_memcpy.c",
        "rvv_strncpy.c",
        "rvv_index.c",
        "rvv_matmul.c",
        "rvv_reduce.c",
        ],
    copts = [
        "-O3",
        "-march=rv64gcv"]
)
