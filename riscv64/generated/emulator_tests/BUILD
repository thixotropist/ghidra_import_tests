# emulate with
# export QEMU_CPU=rv64,zba=true,zbb=true,v=true,vlen=256,vext_spec=v1.0,rvv_ta_all_1s=true,rvv_ma_all_1s=true
# qemu-riscv64-static -L /opt/riscv/sysroot/riscv64-unknown-linux-gnu/ \
#    -E LD_LIBRARY_PATH=/opt/riscv/sysroot/riscv64-unknown-linux-gnu/lib:/opt/riscv/sysroot/lib:/opt/riscv/sysroot/riscv64-unknown-linux-gnu/lib64 \
#    bazel-bin/riscv64/generated/emulator_tests/floatConversions

#
# The test framework is Google's gtest C++
#
cc_binary(
    name = "floatOperationTests",
    srcs = [
        "floatOperationTests.cpp",
        "floatOperations.h",
    ],
    copts = [
        "-std=c++20",
        "-O3",
        "-g",
    ],
    deps = [
        ":floatOperations",
        "@glog",
        "@googletest//:gtest",
    ],
)
#
# Collect the individual operations into a sharable objectr library
# for easier Ghidra analysis
#
cc_library(
    name = "floatOperations",
    srcs = [
        "floatOperations.c",
        "floatOperations.h",
    ],
    copts = [
        "-O3",
        "-g",
        "-march=rv64gcv_zba_zbb_zbc_zbkb_zbkc_zbkx_zvbc_zfh"
    ],
)
#
# Perform semantics/pcode tests with
#    bazel build  --platforms=//riscv64/generated/platforms:riscv_userspace riscv64/generated/emulator_tests:testSemantics

TARGET_ROOT = "/opt/riscv/sysroot"
TARGET_ARCH = "/opt/riscv/sysroot/riscv64-unknown-linux-gnu"

SUPPORT_VECTOR = "v=true,vlen=256,vext_spec=v1.0,rvv_ta_all_1s=true,rvv_ma_all_1s=true"
SUPPORT_BIT_MANIPULATION = "zba=true,zbb=true"
SUPPORT_FLOAT_16 = "zfh=true"
#QEMU = "qemu-riscv64-static"
QEMU = "/opt/riscv/bin/qemu-riscv64"
QEMU_MARCH = SUPPORT_BIT_MANIPULATION + "," + SUPPORT_VECTOR+ "," + SUPPORT_FLOAT_16

genrule(
    name = "testSemantics",
    srcs = [
        ":floatOperations",
        ":floatOperationTests",
    ],
    outs = [":results"],
    cmd = "QEMU_CPU=rv64,{} ".format(QEMU_MARCH) +
        "{} -L {} ".format(QEMU, TARGET_ARCH) +
        "-E LD_LIBRARY_PATH={}/lib64:{}/lib:{}/lib ".format(TARGET_ARCH, TARGET_ARCH, TARGET_ROOT) +
        "$(location :floatOperationTests) > $(location :results)"
)
