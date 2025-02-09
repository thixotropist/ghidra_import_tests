load(":gcc/cc_toolchain_config.bzl", "cc_toolchain_config")
load("//:variables.bzl", "OUTPUT_BASE")

package(default_visibility = ["//visibility:public"])

# These should match a dependency named in MODULE.bazel
SUITE_MODULE = "gcc_riscv_suite"

# This is the gcc version, not the bazel gcc_riscv_suite module version
SUITE_VERSION = "15.0.1"

# the binutils, gcc, and glibc configuration target
SUITE_TARGET = "riscv64-unknown-linux-gnu"

# Bazel currently makes the imported module available at this file system location
PATH_TO_MODULE = OUTPUT_BASE + "/external/" + SUITE_MODULE + "+"

# compiler and linker need to know the imported location of sysroot
SYSROOT = "external/" + SUITE_MODULE + "+/"

# a generic RISCV 64 hart supporting the rva23 ISA profile
constraint_value(
    name = "riscv64",
    constraint_setting = "@@platforms//cpu",
)

# a more advanced RISCV 64 hart supporting the rva23 ISA profile
constraint_value(
    name = "riscv64-rva23-supported",
    constraint_setting = "@@platforms//cpu",
)

# a customized RISCV 64 hart implementing THead extensions as well as rva23 extensions
constraint_value(
    name = "riscv64-thead-supported",
    constraint_setting = "@@platforms//cpu",
)

filegroup(
    name = "empty",
    srcs = [],
)

filegroup(
    name = "objdump",
    srcs =
        [
            "gcc/wrappers/objdump",
        ],
)

filegroup(
    name = "as",
    srcs =
        [
            "gcc/wrappers/as",
        ],
)

# Most compiler and linker actions depend on an imported gcc, local wrappers, and loader scripts
filegroup(
    name = "compiler_files",
    srcs =
        glob(["gcc/wrappers/*"]) + [
            "gcc/elf64lriscv.xc",
            "gcc/elf64lriscv.xdc",
            "@gcc_riscv_suite//:compiler_files",
        ],
)

# This toolchain is for 64 bit user-space platforms implementing the G and C
# ISA

cc_toolchain_config(
    name = "riscv64-gc-gcc-config",
    march = "rv64gc",
)

cc_toolchain(
    name = "riscv64-gc-gcc",
    all_files = ":compiler_files",
    compiler_files = ":compiler_files",
    dwp_files = ":empty",
    linker_files = ":compiler_files",
    as_files = ":compiler_files",
    ar_files = ":compiler_files",
    objcopy_files = ":compiler_files",
    strip_files = ":compiler_files",
    supports_param_files = 0,
    toolchain_config = ":riscv64-gc-gcc-config",
    toolchain_identifier = "riscv64-gc-gcc",
)

toolchain(
    name = "riscv64-gc",
    exec_compatible_with = [
        "@@platforms//cpu:x86_64",
        "@@platforms//os:linux",
    ],
    target_compatible_with = [
        ":riscv64",
    ],
    toolchain = ":riscv64-gc-gcc",
    toolchain_type = "@@bazel_tools//tools/cpp:toolchain_type",
)


# This toolchain is for user-space platforms supporting all of the RVA23
# profile extensions

cc_toolchain_config(name = "riscv64-rva23-gcc-config")

cc_toolchain(
    name = "riscv64-rva23-gcc",
    all_files = ":compiler_files",
    compiler_files = ":compiler_files",
    dwp_files = ":empty",
    linker_files = ":compiler_files",
    as_files = ":compiler_files",
    ar_files = ":compiler_files",
    objcopy_files = ":compiler_files",
    strip_files = ":compiler_files",
    supports_param_files = 0,
    toolchain_config = ":riscv64-rva23-gcc-config",
    toolchain_identifier = "riscv64-rva23-gcc",
)

# currently selected with the riscv64 platform
toolchain(
    name = "riscv64-rva23",
    exec_compatible_with = [
        "@@platforms//cpu:x86_64",
        "@@platforms//os:linux",
    ],
    target_compatible_with = [
        ":riscv64-rva23-supported",
    ],
    toolchain = ":riscv64-rva23-gcc",
    toolchain_type = "@@bazel_tools//tools/cpp:toolchain_type",
)

# This toolchain is for user-space platforms supporting THead
# profile extensions

cc_toolchain_config(
    name = "riscv64-thead-gcc-config",
    march = "rv64gcv_zba_zbb_zbc_zbkb_zbkc_zbkx_zvbc_xtheadba_xtheadbb_xtheadbs_xtheadcmo_xtheadcondmov_xtheadmac_xtheadfmemidx_xtheadmempair_xtheadsync",
)

cc_toolchain(
    name = "riscv64-thead-gcc",
    all_files = ":compiler_files",
    compiler_files = ":compiler_files",
    dwp_files = ":empty",
    linker_files = ":compiler_files",
    as_files = ":compiler_files",
    ar_files = ":compiler_files",
    objcopy_files = ":compiler_files",
    strip_files = ":compiler_files",
    supports_param_files = 0,
    toolchain_config = ":riscv64-thead-gcc-config",
    toolchain_identifier = "riscv64-thead-gcc",
)

# currently selected with the riscv64 platform
toolchain(
    name = "riscv64-thead",
    exec_compatible_with = [
        "@@platforms//cpu:x86_64",
        "@@platforms//os:linux",
    ],
    target_compatible_with = [
        ":riscv64-thead-supported",
    ],
    toolchain = ":riscv64-thead-gcc",
    toolchain_type = "@@bazel_tools//tools/cpp:toolchain_type",
)
