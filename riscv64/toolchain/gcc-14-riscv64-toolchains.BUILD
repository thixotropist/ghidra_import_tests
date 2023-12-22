package(default_visibility = ["//visibility:public"])

# Assign names to different crosscompiler components built on Fedora 38

# runtime files (probably?) needed by all cross compilers
filegroup(
    name = "common_compiler_files",
    srcs = glob([
        "usr/lib/x86_64-linux-gnu/ld-*",
        "usr/lib/x86_64-linux-gnu/libstdc++*",
        "usr/lib/x86_64-linux-gnu/libcc1*",
        "usr/lib/x86_64-linux-gnu/libdl*",
        "usr/lib/x86_64-linux-gnu/libgmp*",
        "usr/lib/x86_64-linux-gnu/libisl*",
        "usr/lib/x86_64-linux-gnu/libm.*",
        "usr/lib/x86_64-linux-gnu/libmvec.*",
        "usr/lib/x86_64-linux-gnu/libmpc.*",
        "usr/lib/x86_64-linux-gnu/libmpfr.so*",
        "usr/lib/x86_64-linux-gnu/libpthread*.so*",
        "usr/lib/x86_64-linux-gnu/libz.so*",
        "usr/lib/x86_64-linux-gnu/libtinfo.so*",
    ]) + [
        "lib",
        "lib64",
        "usr/lib/x86_64-linux-gnu/libc.a",
        "usr/lib/x86_64-linux-gnu/libc.so",
        "usr/lib/x86_64-linux-gnu/libc.so.6",
        "usr/lib/x86_64-linux-gnu/libc_nonshared.a",
        "usr/lib/x86_64-linux-gnu/libopcodes-2.37-system.so",
        "usr/lib/x86_64-linux-gnu/libctf.so.0.0.0",
        "usr/lib/x86_64-linux-gnu/Scrt1.o",
        "usr/lib/x86_64-linux-gnu/crti.o",
        "usr/lib/x86_64-linux-gnu/crt1.o",
        "usr/lib/x86_64-linux-gnu/crtn.o",
        "usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
    ],
)

# riscv64 specific files

filegroup(
    name = "riscv64_all_files",
    srcs = [
        ":common_compiler_files",
        "usr/lib/x86_64-linux-gnu/libopcodes-2.37-riscv64.so",
        "usr/lib/x86_64-linux-gnu/libbfd-2.37-riscv64.so",
        "usr/lib/x86_64-linux-gnu/libctf-nobfd-riscv64.so.0",
        "usr/lib/x86_64-linux-gnu/libctf-nobfd-riscv64.so.0.0.0",
        "usr/lib/x86_64-linux-gnu/libctf-riscv64.so.0",
        "usr/lib/x86_64-linux-gnu/libctf-riscv64.so.0.0.0",
    ] + glob([
        "usr/riscv64-linux-gnu/lib/**",
        "usr/bin/riscv64-linux-gnu*",
        "usr/lib/riscv64-linux-gnu/**",
        "usr/lib/gcc-cross/riscv64-linux-gnu/10/**",
        "usr/riscv64-linux-gnu/include/**",
        "usr/riscv64-linux-gnu/bin/**",
    ]),
)

filegroup(
    name = "std_includes",
    srcs = glob(["sysroot/usr/include/**"]),
)

filegroup(
    name = "riscv64_libexec",
    srcs = glob(["libexec/gcc/riscv64-unknown-linux-gnu/14.0.0/**"]),
)

filegroup(
    name = "riscv64_lib",
    srcs = glob(["lib/gcc/riscv64-unknown-linux-gnu/14/*"])
)

filegroup(
    name = "c++_std_includes",
    srcs = glob(["riscv64-unknown-linux-gnu/include/c++/14.0.0/*"])
)

cc_library(
    name = "c++_iostream_includes",
    hdrs = glob(["riscv64-unknown-linux-gnu/include/c++/14.0.0/*"])
)

cc_library(
    name = "gcc_predef",
    hdrs = ["sysroot/usr/include/stdc-predef.h"]
)

filegroup(
    name = "compiler_files",
    srcs =  [
                ":std_includes",
                ":riscv64_libexec",
                ":riscv64_lib",
                "bin/riscv64-unknown-linux-gnu-cpp",
                "bin/riscv64-unknown-linux-gnu-gcc",
                "bin/riscv64-unknown-linux-gnu-as",
                "bin/riscv64-unknown-linux-gnu-ar",
                "bin/riscv64-unknown-linux-gnu-ld",
                "bin/riscv64-unknown-linux-gnu-ld.bfd",
                "bin/riscv64-unknown-linux-gnu-ranlib",
                ":c++_std_includes",
                "@fedora39-system-libs//:common_compiler_ldd_dependencies",
                ]
)

# binutils and other utility dependencies
filegroup(
    name = "riscv64_binutils_files",
    srcs = [
        "bin/riscv64-unknown-linux-gnu-ar",
        "bin/riscv64-unknown-linux-gnu-as",
        "bin/riscv64-unknown-linux-gnu-elfedit",
        "bin/riscv64-unknown-linux-gnu-gcc-ar",
        "bin/riscv64-unknown-linux-gnu-gcc-nm",
        "bin/riscv64-unknown-linux-gnu-gcc-ranlib",
        "bin/riscv64-unknown-linux-gnu-ld",
        "bin/riscv64-unknown-linux-gnu-ld.bfd",
        "bin/riscv64-unknown-linux-gnu-nm",
        "bin/riscv64-unknown-linux-gnu-objcopy",
        "bin/riscv64-unknown-linux-gnu-objdump",
        "bin/riscv64-unknown-linux-gnu-ranlib",
        "bin/riscv64-unknown-linux-gnu-readelf",
        "bin/riscv64-unknown-linux-gnu-size",
        "bin/riscv64-unknown-linux-gnu-strings",
        "bin/riscv64-unknown-linux-gnu-strip",
    ],
)

# x86_64 files

filegroup(
    name = "x86_64_all_files",
    srcs = [
        ":common_compiler_files",
        #        "usr/lib/x86_64-linux-gnu/libopcodes-system.so",
        #        "usr/lib/x86_64-linux-gnu/libbfd-system.so",
        #        "usr/lib/x86_64-linux-gnu/libctf-nobfd-x86_64.so.0",
        #        "usr/lib/x86_64-linux-gnu/libctf-nobfd-x86_64.so.0.0.0",
    ] + glob([
        "usr/x86_64-linux-gnu/lib/**",
        "usr/bin/x86_64-linux-gnu*",
        "usr/lib/x86_64-linux-gnu/**",
        "usr/lib/gcc-cross/x86_64-linux-gnu/10/**",
        "usr/x86_64-linux-gnu/include/**",
        "usr/x86_64-linux-gnu/bin/**",
        "usr/include/**",
        "usr/lib/gcc/x86_64-linux-gnu/10/include/**",
    ]),
)

filegroup(
    name = "x86_64_std_includes",
    srcs = glob([
        "usr/include/**",
        "usr/lib/gcc/x86_64-linux-gnu/10/include/**",
    ]),
)

# binutils and other utility dependencies
filegroup(
    name = "x86_64_binutils_files",
    srcs = [
        "usr/bin/x86_64-linux-gnu-ar",
        "usr/bin/x86_64-linux-gnu-as",
        "usr/bin/x86_64-linux-gnu-elfedit",
        "usr/bin/x86_64-linux-gnu-gcc-ar-10",
        "usr/bin/x86_64-linux-gnu-gcc-nm-10",
        "usr/bin/x86_64-linux-gnu-gcc-ranlib-10",
        "usr/bin/x86_64-linux-gnu-ld",
        "usr/bin/x86_64-linux-gnu-ld.bfd",
        "usr/bin/x86_64-linux-gnu-objcopy",
        "usr/bin/x86_64-linux-gnu-objdump",
        "usr/bin/x86_64-linux-gnu-ranlib",
        "usr/bin/x86_64-linux-gnu-readelf",
        "usr/bin/x86_64-linux-gnu-strings",
        "usr/bin/x86_64-linux-gnu-strip",
        "usr/lib/x86_64-linux-gnu/libbfd-2.37-system.so",
        "usr/lib/x86_64-linux-gnu/libc.so",
        "usr/lib/x86_64-linux-gnu/libc.so.6",
        "usr/lib/x86_64-linux-gnu/libz.so.1",
    ],
)
