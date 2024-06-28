load(":cc_toolchain_config.bzl", "cc_toolchain_config")
load("//:variables.bzl", "OUTPUT_BASE")
package(default_visibility = ["//visibility:public"])

# These should match a dependency named in MODULE.bazel
SUITE_MODULE = 'gcc_x86_64_suite'
SUITE_VERSION = '15.0.0'

# the binutils, gcc, and glibc configuration target
SUITE_TARGET = 'x86_64-pc-linux-gnu'

# Bazel currently makes the imported module available at this file system location
PATH_TO_MODULE = OUTPUT_BASE + '/external/gcc_x86_64_suite~'

# compiler and linker need to know the imported location of sysroot
SYSROOT = "external/" + SUITE_MODULE + "~/"

# Generate the set of sandbox filesystem directories containing system include files
BUILTIN_INCLUDE_DIRS = [
    PATH_TO_MODULE + '/include',
    PATH_TO_MODULE + '/usr/include',
    PATH_TO_MODULE + '/include/c++/' + SUITE_VERSION,
    PATH_TO_MODULE + '/lib/gcc/' + SUITE_TARGET + '/' + SUITE_VERSION + '/include',
    PATH_TO_MODULE + '/lib/gcc/' + SUITE_TARGET + '/' + SUITE_VERSION + '/include-fixed'
]

constraint_value(
    name = "x86_64",
    constraint_setting = "@platforms//cpu",
)

filegroup(
    name = "empty",
    srcs = [],
)

filegroup(
    name = 'gcc_x86_64_wrappers',
    srcs = glob([
        "gcc-x86_64/imported/*",
    ])
)

filegroup(
    name = 'gcc_compiler_files',
    srcs = [':gcc_x86_64_wrappers',
       '@gcc_x86_64_suite//:compiler_files',
    ]
)

toolchain(
    name = "x86_64_default",
    target_compatible_with = [
        ":x86_64",
    ],
    toolchain = ":x86_64-default-gcc",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)
cc_toolchain(
    name = "x86_64-default-gcc",
    all_files = ":all_files",
    ar_files = ":gcc_compiler_files",
    as_files = ":empty",
    compiler_files = ":gcc_compiler_files",
    dwp_files = ":empty",
    linker_files = ":gcc_compiler_files",
    objcopy_files = ":empty",
    strip_files = ":empty",
    supports_param_files = 0,
    toolchain_config = ":x86_64-default-gcc-config",
    toolchain_identifier = "x86_64-default-gcc",
)

cc_toolchain_config(
    name = "x86_64-default-gcc-config",
    abi_libc_version = ":empty",
    abi_version = ":empty",
    compile_flags = [
        # take the isystem ordering from the output of gcc -xc++ -E -v -
        "--sysroot", SYSROOT,
        "-Wall",
    ],
    compiler = "gcc",
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    cpu = "x86_64",
    cxx_builtin_include_directories = BUILTIN_INCLUDE_DIRS,
    cxx_flags = [
        "-std=c++20",
        "-fno-rtti",
        ],
    dbg_compile_flags = ["-g"],
    host_system_name = ":empty",
    link_flags = ["--sysroot", SYSROOT],
    link_libs = ["-lstdc++", "-lm"],
    opt_compile_flags = [
        "-g0",
        "-Os",
        "-DNDEBUG",
        "-ffunction-sections",
        "-fdata-sections",
    ],
    opt_link_flags = ["-Wl,--gc-sections"],
    supports_start_end_lib = False,
    target_libc = ":empty",
    target_system_name = ":empty",
    tool_paths = {
        "ar": "gcc-x86_64/imported/ar",
        "ld": "gcc-x86_64/imported/ld",
        "cpp": "gcc-x86_64/imported/cpp",
        "gcc": "gcc-x86_64/imported/gcc",
        "dwp": ":empty",
        "gcov": ":empty",
        "nm": "gcc-x86_64/imported/nm",
        "objcopy": "gcc-x86_64/imported/objcopy",
        "objdump": "gcc-x86_64/imported/objdump",
        "strip": "gcc-x86_64/imported/strip",
    },
    toolchain_identifier = "gcc-x86_64",
    unfiltered_compile_flags = [
        "-fno-canonical-system-headers",
        "-Wno-builtin-macro-redefined",
        "-D__DATE__=\"redacted\"",
        "-D__TIMESTAMP__=\"redacted\"",
        "-D__TIME__=\"redacted\"",
    ],
)

toolchain(
    name = "x86_64_local_host",
    target_compatible_with = [
        ":x86_64",
    ],
    toolchain = ":cc-compiler-k8",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)
