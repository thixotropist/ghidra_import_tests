package(default_visibility = ["//visibility:public"])

cc_library(
    name = 'whisper_mocklib',
    srcs = ['mocks.cpp'],
    hdrs = ['mocks.h'],
    defines = [
        'NDEBUG',
        '_XOPEN_SOURCE=600',
        '_GNU_SOURCE',
#        '__riscv_v_intrinsic'
    ],
    copts = [
        '-O3',
        '-ffast-math',
        '-std=c++20',
    ],
)

cc_binary(
    name = 'whisper_mock',
    srcs = ['main.cpp'],
    deps = [':whisper_mocklib'],
    copts = [
        '-O3',
        '-ffast-math',
        '-std=c++20',
    ],
)

# emulate with
# export QEMU_CPU=rv64,zba=true,zbb=true,v=true,vlen=256,vext_spec=v1.0,rvv_ta_all_1s=true,rvv_ma_all_1s=true
# qemu-riscv64-static -L /opt/riscvx -E LD_LIBRARY_PATH=/opt/riscvx/riscv64-unknown-linux-gnu/lib/ bazel-bin/gcc_vectorization/rvv_index_vector

cc_binary(
    name = 'unitTests',
    srcs = ['unitTests.cpp', 'mocks.h'],
    deps = [
        '@whisper_cpp//:whisper',
        '@googletest//:gtest',
        '@glog//:glog'
            ],
    copts = [
        '-std=c++20',
        '-O3',
    ],
)