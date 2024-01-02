load(":cc_toolchain_config.bzl", "cc_toolchain_config")
load("//:variables.bzl", "OUTPUT_BASE")
package(default_visibility = ["//visibility:public"])

constraint_value(
    name = "riscv64",
    constraint_setting = "@platforms//cpu",
)
constraint_value(
    name = "riscv64-v",
    constraint_setting = "@platforms//cpu",
)

filegroup(
    name = "empty",
    srcs = [],
)

# Most compiler and linker actions depend on an imported gcc and local wrappers
filegroup(
    name = 'gcc_13_compiler_files',
    srcs = 
        glob(["gcc-13-riscv/imported/*"]) +
        [
            '@gcc-13-riscv64-toolchains//:compiler_files',
        ]
)

toolchain(
    name = "riscv64-default",
    target_compatible_with = [
        ":riscv64",
    ],
    toolchain = ":riscv64-default-gcc",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)
cc_toolchain(
    name = "riscv64-default-gcc",
    all_files = ":all_files",
    ar_files = ":gcc_13_compiler_files",
    as_files = ":empty",
    compiler_files = ":gcc_13_compiler_files",
    dwp_files = ":empty",
    linker_files = ":gcc_13_compiler_files",
    objcopy_files = ":empty",
    strip_files = ":empty",
    supports_param_files = 0,
    toolchain_config = ":riscv64-default-gcc-config",
    toolchain_identifier = "riscv64-default-gcc",
)

cc_toolchain_config(
    name = "riscv64-default-gcc-config",
    abi_libc_version = ":empty",
    abi_version = ":empty",
    compile_flags = [
        # take the isystem ordering from the output of gcc -xc++ -E -v -
        "--sysroot=external/gcc-13-riscv64-toolchains/sysroot",
        "-Wall",
    ],
    compiler = "gcc",
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    cpu = "riscv64",
    # we really want the following to be constructed from $(output_base) or $(location ...)
    cxx_builtin_include_directories = [
       OUTPUT_BASE + "/external/gcc-13-riscv64-toolchains/sysroot/usr/include",
       OUTPUT_BASE + "/external/gcc-13-riscv64-toolchains/riscv64-unknown-linux-gnu/include/c++/13.2.1",
       OUTPUT_BASE + "/external/gcc-13-riscv64-toolchains/lib/gcc/riscv64-unknown-linux-gnu/13.2.1/include",
       OUTPUT_BASE + "/external/gcc-13-riscv64-toolchains/lib/gcc/riscv64-unknown-linux-gnu/13.2.1/include-fixed",
       ],
    cxx_flags = [
        "-std=c++20",
        "-fno-rtti",
        ],
    dbg_compile_flags = ["-g"],
    host_system_name = ":empty",
    link_flags = [
        "-Wl,--library-path=external/gcc-13-riscv64-toolchains/sysroot/lib",
    ],
    link_libs = ["-lstdc++", "-lm"],
    opt_compile_flags = [
        "-O3",
        "-DNDEBUG",
        "-ffunction-sections",
        "-fdata-sections",
    ],
    opt_link_flags = ["-Wl,--gc-sections"],
    supports_start_end_lib = False,
    target_libc = ":empty",
    target_system_name = ":empty",
    tool_paths = {
        "ar": "gcc-13-riscv/imported/ar",
        "ld": ":empty",
        "cpp": "gcc-13-riscv/imported/cpp",
        "gcc": "gcc-13-riscv/imported/gcc",
        "dwp": ":empty",
        "gcov": ":empty",
        "nm": "gcc-13-riscv/imported/nm",
        "objcopy": "gcc-13-riscv/imported/objcopy",
        "objdump": "gcc-13-riscv/imported/objdump",
        "strip": "gcc-13-riscv/imported/strip",
    },
    toolchain_identifier = "gcc-13-riscv64",
    unfiltered_compile_flags = [
        "-fno-canonical-system-headers",
        "-Wno-builtin-macro-redefined",
        "-D__DATE__=\"redacted\"",
        "-D__TIMESTAMP__=\"redacted\"",
        "-D__TIME__=\"redacted\"",
    ],
)


filegroup(
    name = 'gcc_14_compiler_files',
    srcs = 
        glob(["gcc-14-riscv/imported/*"]) + 
        [
         '@gcc-14-riscv64-toolchains//:compiler_files',
        ]
)

toolchain(
    name = "riscv64-next",
    target_compatible_with = [
        ":riscv64-v",
    ],
    toolchain = ":riscv64-gcc-14",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)
cc_toolchain(
    name = "riscv64-gcc-14",
    all_files = ":all_files",
    ar_files = ":gcc_14_compiler_files",
    as_files = ":empty",
    compiler_files = ":gcc_14_compiler_files",
    dwp_files = ":empty",
    linker_files = ":gcc_14_compiler_files",
    objcopy_files = ":empty",
    strip_files = ":empty",
    supports_param_files = 0,
    toolchain_config = ":riscv64-gcc-14-config",
    toolchain_identifier = "riscv64-gcc-14",
)

cc_toolchain_config(
    name = "riscv64-gcc-14-config",
    abi_libc_version = ":empty",
    abi_version = ":empty",
    compile_flags = [
        # take the isystem ordering from the output of gcc -xc++ -E -v -
        "--sysroot=external/gcc-14-riscv64-toolchains/sysroot",
        "-Wall",
    ],
    compiler = "gcc",
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    cpu = "riscv64",
    # we really want the following to be constructed from $(output_base) or $(location ...)
    cxx_builtin_include_directories = [
       OUTPUT_BASE + "/external/gcc-14-riscv64-toolchains/sysroot/usr/include",
       OUTPUT_BASE + "/external/gcc-14-riscv64-toolchains/riscv64-unknown-linux-gnu/include/c++/14.0.0",
       OUTPUT_BASE + "/external/gcc-14-riscv64-toolchains/lib/gcc/riscv64-unknown-linux-gnu/14.0.0/include",
       OUTPUT_BASE + "/external/gcc-14-riscv64-toolchains/lib/gcc/riscv64-unknown-linux-gnu/14.0.0/include-fixed",
       ],
    cxx_flags = [
        "-std=c++20",
        "-fno-rtti",
        ],
    dbg_compile_flags = ["-g"],
    host_system_name = ":empty",
    link_flags = [
        "-Wl,--library-path=external/gcc-14-riscv64-toolchains/sysroot/usr/lib",
    ],
    link_libs = ["-lstdc++", "-lm"],
    opt_compile_flags = [
        "-O3",
        "-DNDEBUG",
        "-ffunction-sections",
        "-fdata-sections",
    ],
    opt_link_flags = [
        "-Wl,--gc-sections",
        ],
    supports_start_end_lib = False,
    target_libc = ":empty",
    target_system_name = ":empty",
    tool_paths = {
        "ar": "gcc-14-riscv/imported/ar",
        "ld": ":empty",
        "cpp": "gcc-14-riscv/imported/cpp",
        "gcc": "gcc-14-riscv/imported/gcc",
        "dwp": ":empty",
        "gcov": ":empty",
        "nm": "gcc-14-riscv/imported/nm",
        "objcopy": "gcc-14-riscv/imported/objcopy",
        "objdump": "gcc-14-riscv/imported/objdump",
        "strip": "gcc-14-riscv/imported/strip",
    },
    toolchain_identifier = "gcc-14-riscv64",
    unfiltered_compile_flags = [
        
        "-Wno-builtin-macro-redefined",
        "-D__DATE__=\"redacted\"",
        "-D__TIMESTAMP__=\"redacted\"",
        "-D__TIME__=\"redacted\"",
    ],
)
