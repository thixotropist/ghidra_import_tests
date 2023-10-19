package(default_visibility = ["//visibility:public"])

# Assign names to different crosscompiler components built on Fedora 38

filegroup(
    name = "std_includes",
    srcs = glob(["sysroot/usr/include/**"]),
)

filegroup(
    name = "riscv64_libexec",
    srcs = glob(["libexec/gcc/riscv64-unknown-linux-gnu/13.2.1/**"]),
)

filegroup(
    name = "riscv64_lib",
    srcs = glob(["lib/gcc/riscv64-unknown-linux-gnu/13/*"])
)

filegroup(
    name = "c++_std_includes",
    srcs = glob(["riscv64-unknown-linux-gnu/include/c++/13.2.1/*"])
)

cc_library(
    name = "c++_iostream_includes",
    hdrs = glob(["riscv64-unknown-linux-gnu/include/c++/13.2.1/*"])
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
                "@fedora38-system-libs//:common_compiler_ldd_dependencies",
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
