# emulate with
# export QEMU_CPU=rv64,zba=true,zbb=true,v=true,vlen=256,vext_spec=v1.0,rvv_ta_all_1s=true,rvv_ma_all_1s=true
# qemu-riscv64-static -L /opt/riscv/sysroot/riscv64-unknown-linux-gnu/ \
#    -E LD_LIBRARY_PATH=/opt/riscv/sysroot/riscv64-unknown-linux-gnu/lib:/opt/riscv/sysroot/lib:/opt/riscv/sysroot/riscv64-unknown-linux-gnu/lib64 \
#    bazel-bin/riscv64/generated/emulator_tests/floatConversions

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
