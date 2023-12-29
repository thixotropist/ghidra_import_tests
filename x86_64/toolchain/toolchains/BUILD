load(":cc_toolchain_config.bzl", "cc_toolchain_config")
load("//:variables.bzl", "OUTPUT_BASE")
package(default_visibility = ["//visibility:public"])

constraint_value(
    name = "x86_64",
    constraint_setting = "@platforms//cpu",
)

filegroup(
    name = "empty",
    srcs = [],
)

##### x86_64 #####

filegroup(
    name = 'gcc_14_x86_64_wrappers',
    srcs = glob([
        "gcc-14-x86_64/imported/*",
    ])
)

filegroup(
    name = 'gcc_14_compiler_files',
    srcs = [':gcc_14_x86_64_wrappers',
       '@gcc-14-x86_64-toolchains//:compiler_files',
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
    ar_files = ":gcc_14_compiler_files",
    as_files = ":empty",
    compiler_files = ":gcc_14_compiler_files",
    dwp_files = ":empty",
    linker_files = ":gcc_14_compiler_files",
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
        "--sysroot", "external/gcc-14-x86_64-toolchains/sysroot/",
        "-Wall",
    ],
    compiler = "gcc",
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    cpu = "x86_64",
    # we really want the following to be constructed from $(output_base) or $(location ...)
    cxx_builtin_include_directories = [
       OUTPUT_BASE + "/external/gcc-14-x86_64-toolchains/sysroot/usr/include",
       OUTPUT_BASE + "/external/gcc-14-x86_64-toolchains/include",
       OUTPUT_BASE + "/external/gcc-14-x86_64-toolchains/include/c++/14.0.0",
#      OUTPUT_BASE + "/external/gcc-14-x86_64-toolchains/x86_64-pc-linux-gnu/include/c++/14.0.0",
       OUTPUT_BASE + "/external/gcc-14-x86_64-toolchains/lib/gcc/x86_64-pc-linux-gnu/14.0.0/include",
       OUTPUT_BASE + "/external/gcc-14-x86_64-toolchains/lib/gcc/x86_64-pc-linux-gnu/14.0.0/include-fixed",
       ],
    cxx_flags = [
        "-std=c++20",
        "-fno-rtti",
        ],
    dbg_compile_flags = ["-g"],
    host_system_name = ":empty",
    link_flags = ["--sysroot", "external/gcc-14-x86_64-toolchains/sysroot/"],
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
        "ar": "gcc-14-x86_64/imported/ar",
        "ld": "gcc-14-x86_64/imported/ld",
        "cpp": "gcc-14-x86_64/imported/cpp",
        "gcc": "gcc-14-x86_64/imported/gcc",
        "dwp": ":empty",
        "gcov": ":empty",
        "nm": "gcc-14-x86_64/imported/nm",
        "objcopy": "gcc-14-x86_64/imported/objcopy",
        "objdump": "gcc-14-x86_64/imported/objdump",
        "strip": "gcc-14-x86_64/imported/strip",
    },
    toolchain_identifier = "gcc-14-x86_64",
    unfiltered_compile_flags = [
        "-fno-canonical-system-headers",
        "-Wno-builtin-macro-redefined",
        "-D__DATE__=\"redacted\"",
        "-D__TIMESTAMP__=\"redacted\"",
        "-D__TIME__=\"redacted\"",
    ],
)

filegroup(
    name = 'gcc14_compiler_files',
    srcs = [':gcc_14_x86__wrappers',
       '@gcc-14-x86_64-toolchains//:compiler_files',
    ]
)

toolchain(
    name = "x86_64_local_host",
    target_compatible_with = [
        ":x86_64",
    ],
    toolchain = ":cc-compiler-k8",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)
