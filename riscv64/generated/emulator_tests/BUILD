# emulate with
# export QEMU_CPU=rv64,zba=true,zbb=true,v=true,vlen=256,vext_spec=v1.0,rvv_ta_all_1s=true,rvv_ma_all_1s=true
# qemu-riscv64-static -L /opt/riscv/sysroot/riscv64-unknown-linux-gnu/ \
#    -E LD_LIBRARY_PATH=/opt/riscv/sysroot/riscv64-unknown-linux-gnu/lib:/opt/riscv/sysroot/lib:/opt/riscv/sysroot/riscv64-unknown-linux-gnu/lib64 \
#    bazel-bin/riscv64/generated/emulator_tests/floatConversions

#
# The test framework is Google's gtest C++
#
cc_binary(
    name = "floatConversionTests",
    srcs = [
        "floatConversionTests.cpp",
        "floatConversions.h",
    ],
    copts = [
        "-std=c++20",
        "-O3",
        "-g",
    ],
    deps = [
        ":floatConversions",
        "@glog",
        "@googletest//:gtest",
    ],
)
#
# Collect the individual operations into a sharable objectr library
# for easier Ghidra analysis
#
cc_library(
    name = "floatConversions",
    srcs = [
        "floatConversions.c",
        "floatConversions.h",
    ],
    copts = [
        "-O3",
        "-g",
    ],
)
#
# Perform semantics/pcode tests with
#    bazel build  --platforms=//riscv64/generated/platforms:riscv_userspace riscv64/generated/emulator_tests:testSemantics

TARGET_ROOT = "/opt/riscv/sysroot"
TARGET_ARCH = "/opt/riscv/sysroot/riscv64-unknown-linux-gnu"

QEMU_MARCH = "zba=true,zbb=true,v=true,vlen=256,vext_spec=v1.0,rvv_ta_all_1s=true,rvv_ma_all_1s=true"

genrule(
    name = "testSemantics",
    srcs = [
        ":floatConversions",
        ":floatConversionTests",
    ],
    outs = [":results"],
    cmd = "QEMU_CPU=rv64,{} ".format(QEMU_MARCH) +
        "qemu-riscv64-static -L {} ".format(TARGET_ARCH, TARGET_ARCH) +
        "-E LD_LIBRARY_PATH={}/lib64:{}/lib:{}/lib ".format(TARGET_ARCH, TARGET_ARCH, TARGET_ROOT) +
        "$(location :floatConversionTests) > $(location :results)"
)
