load(":cc_toolchain_config.bzl", "cc_toolchain_config")
load("//:variables.bzl", "OUTPUT_BASE")
package(default_visibility = ["//visibility:public"])

# These should match a dependency named in MODULE.bazel
SUITE_MODULE = 'gcc_riscv_suite'
SUITE_VERSION = '15.0.0'

# the binutils, gcc, and glibc configuration target
SUITE_TARGET = 'riscv64-unknown-linux-gnu'

# Bazel currently makes the imported module available at this file system location
PATH_TO_MODULE = OUTPUT_BASE + '/external/' + SUITE_MODULE + '~'

# compiler and linker need to know the imported location of sysroot
SYSROOT = "external/" + SUITE_MODULE + '~/'

# Generate the set of sandbox filesystem directories containing system include files
BUILTIN_INCLUDE_DIRS = [
    PATH_TO_MODULE + '/include',
    PATH_TO_MODULE + '/usr/include',
    PATH_TO_MODULE + '/' + SUITE_TARGET + '/include/c++/' + SUITE_VERSION,
    PATH_TO_MODULE + '/lib/gcc/' + SUITE_TARGET + '/' + SUITE_VERSION + '/include',
    PATH_TO_MODULE + '/lib/gcc/' + SUITE_TARGET + '/' + SUITE_VERSION + '/include-fixed'
]

# a generic RISCV 64 hart supporting march=rv64gc
constraint_value(
    name = "riscv64",
    constraint_setting = "@platforms//cpu",
)
# a vector RISCV 64 hart supporting march=rv64gcv
constraint_value(
    name = "riscv64-v",
    constraint_setting = "@platforms//cpu",
)

# a customized RISCV 64 hart supporting march=rv64gcv plus other extensions supported by binutils
constraint_value(
    name = "riscv64-c",
    constraint_setting = "@platforms//cpu",
)


# a local (non-hermetic) toolchain platform for sandbox debugging
constraint_value(
    name = "riscv64-l",
    constraint_setting = "@platforms//cpu",
)

filegroup(
    name = "empty",
    srcs = [],
)

# Most compiler and linker actions depend on an imported gcc and local wrappers
filegroup(
    name = 'gcc_riscv64_compiler_files',
    srcs = 
        glob(["gcc-riscv/imported/*"]) +
        [
            '@gcc_riscv_suite//:compiler_files',
        ]
)

filegroup(
    name = 'gcc_riscv_objdump',
    srcs = 
        [
            'gcc-riscv/imported/objdump',
        ]
)

filegroup(
    name = 'gcc_riscv_as',
    srcs = 
        [
            'gcc-riscv/imported/as',
        ]
)

# currently selected with the riscv_userspace platform
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
    all_files = ":gcc_riscv64_compiler_files",
    ar_files = ":gcc_riscv64_compiler_files",
    as_files = ":empty",
    compiler_files = ":gcc_riscv64_compiler_files",
    dwp_files = ":empty",
    linker_files = ":gcc_riscv64_compiler_files",
    objcopy_files = ":empty",
    strip_files = ":gcc_riscv64_compiler_files",
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
        "--sysroot=" + SYSROOT,
        "-Wall",
    ],
    compiler = "gcc",
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    cpu = "riscv64",
    # we really want the following to be constructed from $(output_base) or $(location ...)
    cxx_builtin_include_directories = BUILTIN_INCLUDE_DIRS,
    cxx_flags = [
        "-std=c++20",
        "-fno-rtti",
        ],
    dbg_compile_flags = ["-g"],
    host_system_name = ":empty",
    link_flags = [
        "-Wl,--library-path=" + SYSROOT + "/lib",
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
        "ar": "gcc-riscv/imported/ar",
        "ld": ":empty",
        "cpp": "gcc-riscv/imported/cpp",
        "gcc": "gcc-riscv/imported/gcc",
        "dwp": ":empty",
        "gcov": ":empty",
        "nm": "gcc-riscv/imported/nm",
        "objcopy": "gcc-riscv/imported/objcopy",
        "objdump": "gcc-riscv/imported/objdump",
        "strip": "gcc-riscv/imported/strip",
    },
    toolchain_identifier = "gcc-riscv64",
    unfiltered_compile_flags = [
        "-fno-canonical-system-headers",
        "-Wno-builtin-macro-redefined",
        "-D__DATE__=\"redacted\"",
        "-D__TIMESTAMP__=\"redacted\"",
        "-D__TIME__=\"redacted\"",
    ],
)

# currently selected with the riscv_vector platform
toolchain(
    name = "riscv64-vector",
    target_compatible_with = [
        ":riscv64-v",
    ],
    toolchain = ":riscv64-vector-gcc",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)
cc_toolchain(
    name = "riscv64-vector-gcc",
    all_files = ":gcc_riscv64_compiler_files",
    ar_files = ":gcc_riscv64_compiler_files",
    as_files = ":empty",
    compiler_files = ":gcc_riscv64_compiler_files",
    dwp_files = ":empty",
    linker_files = ":gcc_riscv64_compiler_files",
    objcopy_files = ":empty",
    strip_files = ":gcc_riscv64_compiler_files",
    supports_param_files = 0,
    toolchain_config = ":riscv64-vector-gcc-config",
    toolchain_identifier = "riscv64-vector-gcc",
)

cc_toolchain_config(
    name = "riscv64-vector-gcc-config",
    abi_libc_version = ":empty",
    abi_version = ":empty",
    compile_flags = [
        "--sysroot=" + SYSROOT,
        "-Wall",
        "-march=rv64gcv"
    ],
    compiler = "gcc",
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    cpu = "riscv64",
    # we really want the following to be constructed from $(output_base) or $(location ...)
    cxx_builtin_include_directories = BUILTIN_INCLUDE_DIRS,
    cxx_flags = [
        "-std=c++20",
        "-fno-rtti",
        ],
    dbg_compile_flags = ["-g"],
    host_system_name = ":empty",
    link_flags = [
        "-Wl,--library-path=" + SYSROOT + "/lib",
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
        "ar": "gcc-riscv/imported/ar",
        "ld": ":empty",
        "cpp": "gcc-riscv/imported/cpp",
        "gcc": "gcc-riscv/imported/gcc",
        "dwp": ":empty",
        "gcov": ":empty",
        "nm": "gcc-riscv/imported/nm",
        "objcopy": "gcc-riscv/imported/objcopy",
        "objdump": "gcc-riscv/imported/objdump",
        "strip": "gcc-riscv/imported/strip",
    },
    toolchain_identifier = "riscv64-vector-gcc",
    unfiltered_compile_flags = [
        "-fno-canonical-system-headers",
        "-Wno-builtin-macro-redefined",
        "-D__DATE__=\"redacted\"",
        "-D__TIMESTAMP__=\"redacted\"",
        "-D__TIME__=\"redacted\"",
    ],
)

# a toolchain for processors supporting lots of ISA extensions, including the vendor extension platform
toolchain(
    name = "riscv64-custom",
    target_compatible_with = [
        ":riscv64-c",
    ],
    toolchain = ":riscv64-custom-gcc",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)

cc_toolchain(
    name = "riscv64-custom-gcc",
    all_files = ":gcc_riscv64_compiler_files",
    ar_files = ":gcc_riscv64_compiler_files",
    as_files = ":empty",
    compiler_files = ":gcc_riscv64_compiler_files",
    dwp_files = ":empty",
    linker_files = ":gcc_riscv64_compiler_files",
    objcopy_files = ":empty",
    strip_files = ":empty",
    supports_param_files = 0,
    toolchain_config = ":riscv64-custom-gcc-config",
    toolchain_identifier = "riscv64-custom-gcc",
)

cc_toolchain_config(
    name = "riscv64-custom-gcc-config",
    abi_libc_version = ":empty",
    abi_version = ":empty",
    compile_flags = [
        # take the isystem ordering from the output of gcc -xc++ -E -v -
        "--sysroot=" + SYSROOT,
        "-Wall",
        "-march=rv64gcv_zba_zbb_zbc_zbkb_zbkc_zbkx_zvbc_xtheadba_xtheadbb_xtheadbs_xtheadcmo_xtheadcondmov_xtheadmac_xtheadfmemidx_xtheadmempair_xtheadsync",
    ],
    compiler = "gcc",
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    cpu = "riscv64",
    # we really want the following to be constructed from $(output_base) or $(location ...)
    cxx_builtin_include_directories = BUILTIN_INCLUDE_DIRS,
    cxx_flags = [
        "-std=c++20",
        "-fno-rtti",
        ],
    dbg_compile_flags = ["-g"],
    host_system_name = ":empty",
    link_flags = [
        "-Wl,--library-path=" + SYSROOT + "/lib",
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
        "ar": "gcc-riscv/imported/ar",
        "ld": ":empty",
        "cpp": "gcc-riscv/imported/cpp",
        "gcc": "gcc-riscv/imported/gcc",
        "dwp": ":empty",
        "gcov": ":empty",
        "nm": "gcc-riscv/imported/nm",
        "objcopy": "gcc-riscv/imported/objcopy",
        "objdump": "gcc-riscv/imported/objdump",
        "strip": "gcc-riscv/imported/strip",
    },
    toolchain_identifier = "gcc-riscv64",
    unfiltered_compile_flags = [
        "-fno-canonical-system-headers",
        "-Wno-builtin-macro-redefined",
        "-D__DATE__=\"redacted\"",
        "-D__TIMESTAMP__=\"redacted\"",
        "-D__TIME__=\"redacted\"",
    ],
)

# a toolchain for debugging sandbox problems - the compiler suite must be installed locally

toolchain(
    name = "riscv64-local",
    target_compatible_with = [
        ":riscv64-l",
    ],
    toolchain = ":riscv64-local-gcc",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)

cc_toolchain(
    name = "riscv64-local-gcc",
    all_files = ":empty",
    ar_files = ":empty",
    as_files = ":empty",
    compiler_files = ":empty",
    dwp_files = ":empty",
    linker_files = ":empty",
    objcopy_files = ":empty",
    strip_files = ":empty",
    supports_param_files = 0,
    toolchain_config = ":riscv64-local-gcc-config",
    toolchain_identifier = "riscv64-local-gcc",
)
cc_toolchain_config(
    name = "riscv64-local-gcc-config",
    abi_libc_version = ":empty",
    abi_version = ":empty",
    compile_flags = [
        # take the isystem ordering from the output of gcc -xc++ -E -v -
        "-Wall",
    ],
    compiler = "gcc",
    coverage_compile_flags = ["--coverage"],
        coverage_link_flags = ["--coverage"],
    cpu = "riscv64",
    # we really want the following to be constructed from $(output_base) or $(location ...)
    cxx_builtin_include_directories = [
       "/opt/riscv/sysroot/usr/include",
       "/opt/riscv/riscv64-unknown-linux-gnu/include/c++/14.1.0",
       "/opt/riscv/lib/gcc/riscv64-unknown-linux-gnu/14.1.0/include",
       "/opt/riscv/lib/gcc/riscv64-unknown-linux-gnu/14.1.0/include-fixed",
       ],
    cxx_flags = [
        "-std=c++20",
        "-fno-rtti",
        ],
    dbg_compile_flags = ["-g"],
    host_system_name = ":empty",
    link_flags = [
        "-Wl,--library-path=/opt/riscv/sysroot/lib",
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
        "ar": "/opt/riscv/bin/riscv64-unknown-linux-gnu-ar",
        "ld": ":empty",
        "cpp": "/opt/riscv/bin/riscv64-unknown-linux-gnu-cpp",
        "gcc": "/opt/riscv/bin/riscv64-unknown-linux-gnu-gcc",
        "dwp": ":empty",
        "gcov": ":empty",
        "nm": "/opt/riscv/bin/riscv64-unknown-linux-gnu-gcc-nm",
        "objcopy": "/opt/riscv/bin/riscv64-unknown-linux-gnu-objcopy",
        "objdump": "/opt/riscv/bin/riscv64-unknown-linux-gnu-objdump",
        "strip": "/opt/riscv/bin/riscv64-unknown-linux-gnu-strip",
    },
    toolchain_identifier = "gcc-riscv64-local",
    unfiltered_compile_flags = [
        "-fno-canonical-system-headers",
        "-Wno-builtin-macro-redefined",
        "-D__DATE__=\"redacted\"",
        "-D__TIMESTAMP__=\"redacted\"",
        "-D__TIME__=\"redacted\"",
    ],
)
