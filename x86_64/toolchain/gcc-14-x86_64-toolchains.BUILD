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

# x86_64 gcc specific files

filegroup(
    name = "x86_64_all_files",
    srcs = [
        ":common_compiler_files",
        "usr/lib/x86_64-linux-gnu/libopcodes-2.37-x86_64.so",
        "usr/lib/x86_64-linux-gnu/libbfd-2.37-x86_64.so",
        "usr/lib/x86_64-linux-gnu/libctf-nobfd-x86_64.so.0",
        "usr/lib/x86_64-linux-gnu/libctf-nobfd-x86_64.so.0.0.0",
        "usr/lib/x86_64-linux-gnu/libctf-x86_64.so.0",
        "usr/lib/x86_64-linux-gnu/libctf-x86_64.so.0.0.0",
    ] + glob([
        "usr/x86_64-linux-gnu/lib/**",
        "usr/bin/x86_64-linux-gnu*",
        "usr/lib/x86_64-linux-gnu/**",
        "usr/lib/gcc-cross/x86_64-linux-gnu/10/**",
        "usr/x86_64-linux-gnu/include/**",
        "usr/x86_64-linux-gnu/bin/**",
    ]),
)

filegroup(
    name = "std_includes",
    srcs = glob(["sysroot/usr/include/**"]),
)

filegroup(
    name = "x86_64_libexec",
    srcs = glob(["libexec/gcc/x86_64-pc-linux-gnu/14.0.0/**"]),
)

filegroup(
    name = "x86_64_lib",
    srcs = glob(["lib/gcc/x86_64-pc-linux-gnu/14.0.0/**"])
)

filegroup(
    name = "c++_std_includes",
    srcs = glob(["x86_64-pc-linux-gnu/include/c++/14.0.0/*"])
)

cc_library(
    name = "c++_iostream_includes",
    hdrs = glob(["x86_64-pc-linux-gnu/include/c++/14.0.0/*"])
)

cc_library(
    name = "gcc_predef",
    hdrs = ["sysroot/usr/include/stdc-predef.h"]
)

filegroup(
    name = "compiler_files",
    srcs =  [
                ":std_includes",
                ":x86_64_libexec",
                ":x86_64_lib",
                "bin/cpp",
                "bin/gcc",
                "bin/as",
                "bin/ar",
                "bin/ld",
                "bin/ld.bfd",
                "bin/ranlib",
                ":c++_std_includes",
                "@fedora39-system-libs//:common_compiler_ldd_dependencies",
                ]
)

# binutils and other utility dependencies
filegroup(
    name = "x86_64_binutils_files",
    srcs = [
        "bin/x86_64-pc-linux-gnu-ar",
        "bin/x86_64-pc-linux-gnu-as",
        "bin/x86_64-pc-linux-gnu-elfedit",
        "bin/x86_64-pc-linux-gnu-gcc-ar",
        "bin/x86_64-pc-linux-gnu-gcc-nm",
        "bin/x86_64-pc-linux-gnu-gcc-ranlib",
        "bin/x86_64-pc-linux-gnu-ld",
        "bin/x86_64-pc-linux-gnu-ld.bfd",
        "bin/x86_64-pc-linux-gnu-nm",
        "bin/x86_64-pc-linux-gnu-objcopy",
        "bin/x86_64-pc-linux-gnu-objdump",
        "bin/x86_64-pc-linux-gnu-ranlib",
        "bin/x86_64-pc-linux-gnu-readelf",
        "bin/x86_64-pc-linux-gnu-size",
        "bin/x86_64-pc-linux-gnu-strings",
        "bin/x86_64-pc-linux-gnu-strip",
    ],
)
