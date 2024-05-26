load(":cc_toolchain_config.bzl", "cc_toolchain_config")
load("//:variables.bzl", "OUTPUT_BASE")
package(default_visibility = ["//visibility:public"])

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

# an x86_64 toolchain used in unit tests
constraint_value(
    name = "x86_64",
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
    name = 'gcc_14_riscv64_compiler_files',
    srcs = 
        glob(["gcc-14-riscv/imported/*"]) +
        [
            '@gcc-14-riscv64-suite//:compiler_files',
        ]
)

filegroup(
    name = 'gcc_14_riscv64_objdump',
    srcs = 
        [
            'gcc-14-riscv/imported/objdump',
        ]
)

filegroup(
    name = 'gcc_14_riscv64_as',
    srcs = 
        [
            'gcc-14-riscv/imported/as',
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
    all_files = ":gcc_14_riscv64_compiler_files",
    ar_files = ":gcc_14_riscv64_compiler_files",
    as_files = ":empty",
    compiler_files = ":gcc_14_riscv64_compiler_files",
    dwp_files = ":empty",
    linker_files = ":gcc_14_riscv64_compiler_files",
    objcopy_files = ":empty",
    strip_files = ":gcc_14_riscv64_compiler_files",
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
        "--sysroot=external/gcc-14-riscv64-suite/",
        "-Wall",
    ],
    compiler = "gcc",
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    cpu = "riscv64",
    # we really want the following to be constructed from $(output_base) or $(location ...)
    cxx_builtin_include_directories = [
       OUTPUT_BASE + "/external/gcc-14-riscv64-suite/usr/include",
       OUTPUT_BASE + "/external/gcc-14-riscv64-suite/riscv64-unknown-linux-gnu/include/c++/14.1.0",
       OUTPUT_BASE + "/external/gcc-14-riscv64-suite/lib/gcc/riscv64-unknown-linux-gnu/14.1.0/include",
       OUTPUT_BASE + "/external/gcc-14-riscv64-suite/lib/gcc/riscv64-unknown-linux-gnu/14.1.0/include-fixed",
       ],
    cxx_flags = [
        "-std=c++20",
        "-fno-rtti",
        ],
    dbg_compile_flags = ["-g"],
    host_system_name = ":empty",
    link_flags = [
        "-Wl,--library-path=external/gcc-14-riscv64-suite/lib",
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
        "-fno-canonical-system-headers",
        "-Wno-builtin-macro-redefined",
        "-D__DATE__=\"redacted\"",
        "-D__TIMESTAMP__=\"redacted\"",
        "-D__TIME__=\"redacted\"",
    ],
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
    all_files = ":gcc_14_riscv64_compiler_files",
    ar_files = ":gcc_14_riscv64_compiler_files",
    as_files = ":empty",
    compiler_files = ":gcc_14_riscv64_compiler_files",
    dwp_files = ":empty",
    linker_files = ":gcc_14_riscv64_compiler_files",
    objcopy_files = ":empty",
    strip_files = ":gcc_14_riscv64_compiler_files",
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
        "--sysroot=external/gcc-14-riscv64-suite",
        "-Wall",
        "-march=rv64gcv",
    ],
    compiler = "gcc",
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    cpu = "riscv64",
    # we really want the following to be constructed from $(output_base) or $(location ...)
    cxx_builtin_include_directories = [
       OUTPUT_BASE + "/external/gcc-14-riscv64-suite/sysroot/usr/include",
       OUTPUT_BASE + "/external/gcc-14-riscv64-suite/riscv64-unknown-linux-gnu/include/c++/14.1.0",
       OUTPUT_BASE + "/external/gcc-14-riscv64-suite/lib/gcc/riscv64-unknown-linux-gnu/14.1.0/include",
       OUTPUT_BASE + "/external/gcc-14-riscv64-suite/lib/gcc/riscv64-unknown-linux-gnu/14.1.0/include-fixed",
       ],
    cxx_flags = [
        "-std=c++20",
        "-fno-rtti",
        ],
    dbg_compile_flags = ["-g"],
    host_system_name = ":empty",
    link_flags = [
        "-Wl,--library-path=external/gcc-14-riscv64-suite/sysroot/usr/lib",
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
# a toolchain for processors supporting lots of ISA extensions
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
    all_files = ":gcc_14_riscv64_compiler_files",
    ar_files = ":gcc_14_riscv64_compiler_files",
    as_files = ":empty",
    compiler_files = ":gcc_14_riscv64_compiler_files",
    dwp_files = ":empty",
    linker_files = ":gcc_14_riscv64_compiler_files",
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
        "--sysroot=external/gcc-14-riscv64-suite/",
        "-Wall",
        "-march=rv64gcv_zba_zbb_zbc_zbkb_zbkc_zbkx_zvbc_xtheadba_xtheadbb_xtheadbs_xtheadcmo_xtheadcondmov_xtheadmac_xtheadfmemidx_xtheadmempair_xtheadsync",
    ],
    compiler = "gcc",
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    cpu = "riscv64",
    # we really want the following to be constructed from $(output_base) or $(location ...)
    cxx_builtin_include_directories = [
       OUTPUT_BASE + "/external/gcc-14-riscv64-suite/sysroot/usr/include",
       OUTPUT_BASE + "/external/gcc-14-riscv64-suite/riscv64-unknown-linux-gnu/include/c++/14.1.0",
       OUTPUT_BASE + "/external/gcc-14-riscv64-suite/lib/gcc/riscv64-unknown-linux-gnu/14.1.0/include",
       OUTPUT_BASE + "/external/gcc-14-riscv64-suite/lib/gcc/riscv64-unknown-linux-gnu/14.1.0/include-fixed",
       ],
    cxx_flags = [
        "-std=c++20",
        "-fno-rtti",
        ],
    dbg_compile_flags = ["-g"],
    host_system_name = ":empty",
    link_flags = [
        "-Wl,--library-path=external/gcc-14-riscv64-suite/sysroot/lib",
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
       "/opt/riscvx/sysroot/usr/include",
       "/opt/riscvx/riscv64-unknown-linux-gnu/include/c++/14.1.0",
       "/opt/riscvx/lib/gcc/riscv64-unknown-linux-gnu/14.1.0/include",
       "/opt/riscvx/lib/gcc/riscv64-unknown-linux-gnu/14.1.0/include-fixed",
       ],
    cxx_flags = [
        "-std=c++20",
        "-fno-rtti",
        ],
    dbg_compile_flags = ["-g"],
    host_system_name = ":empty",
    link_flags = [
        "-Wl,--library-path=/opt/riscvx/sysroot/lib",
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
        "ar": "/opt/riscvx/bin/riscv64-unknown-linux-gnu-ar",
        "ld": ":empty",
        "cpp": "/opt/riscvx/bin/riscv64-unknown-linux-gnu-cpp",
        "gcc": "/opt/riscvx/bin/riscv64-unknown-linux-gnu-gcc",
        "dwp": ":empty",
        "gcov": ":empty",
        "nm": "/opt/riscvx/bin/riscv64-unknown-linux-gnu-gcc-nm",
        "objcopy": "/opt/riscvx/bin/riscv64-unknown-linux-gnu-objcopy",
        "objdump": "/opt/riscvx/bin/riscv64-unknown-linux-gnu-objdump",
        "strip": "/opt/riscvx/bin/riscv64-unknown-linux-gnu-strip",
    },
    toolchain_identifier = "gcc-14-riscv64-local",
    unfiltered_compile_flags = [
        "-fno-canonical-system-headers",
        "-Wno-builtin-macro-redefined",
        "-D__DATE__=\"redacted\"",
        "-D__TIMESTAMP__=\"redacted\"",
        "-D__TIME__=\"redacted\"",
    ],
)

##### x86_64 for local unit tests#####

filegroup(
    name = 'gcc_14_x86_64_wrappers',
    srcs = glob([
        "gcc-14-x86_64/imported/*",
    ])
)

filegroup(
    name = 'gcc_14_x86_64_compiler_files',
    srcs = [':gcc_14_x86_64_wrappers',
       '@gcc-14-x86_64-suite//:compiler_files',
    ]
)

toolchain(
    name = "x86_64-next",
    target_compatible_with = [
        ":x86_64",
    ],
    toolchain = ":x86_64-default-gcc",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)
cc_toolchain(
    name = "x86_64-default-gcc",
    all_files = ":gcc_14_x86_64_compiler_files",
    ar_files = ":gcc_14_x86_64_compiler_files",
    as_files = ":empty",
    compiler_files = ":gcc_14_x86_64_compiler_files",
    dwp_files = ":empty",
    linker_files = ":gcc_14_x86_64_compiler_files",
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
        "--sysroot", "external/gcc-14-x86_64-suite/",
        "-Wall",
    ],
    compiler = "gcc",
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    cpu = "x86_64",
    # we really want the following to be constructed from $(output_base) or $(location ...)
    cxx_builtin_include_directories = [
       OUTPUT_BASE + "/external/gcc-14-x86_64-suite/include",
       OUTPUT_BASE + "/external/gcc-14-x86_64-suite/usr/include",
       OUTPUT_BASE + "/external/gcc-14-x86_64-suite/include/c++/14.1.0",
#      OUTPUT_BASE + "/external/gcc-14-x86_64-suite/x86_64-pc-linux-gnu/include/c++/14.1.0",
       OUTPUT_BASE + "/external/gcc-14-x86_64-suite/lib/gcc/x86_64-pc-linux-gnu/14.1.0/include",
       OUTPUT_BASE + "/external/gcc-14-x86_64-suite/lib/gcc/x86_64-pc-linux-gnu/14.1.0/include-fixed",
       ],
    cxx_flags = [
        "-std=c++20",
        "-fno-rtti",
        ],
    dbg_compile_flags = ["-g"],
    host_system_name = ":empty",
    link_flags = ["--sysroot", "external/gcc-14-x86_64-suite/"],
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

