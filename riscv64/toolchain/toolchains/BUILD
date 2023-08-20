load(":cc_toolchain_config.bzl", "cc_toolchain_config")
load("//:variables.bzl", "OUTPUT_BASE")
package(default_visibility = ["//visibility:public"])

constraint_value(
    name = "riscv64",
    constraint_setting = "@platforms//cpu",
)

constraint_value(
    name = "x86_64",
    constraint_setting = "@platforms//cpu",
)

filegroup(
    name = "empty",
    srcs = [],
)

##### riscv64 #####

filegroup(
    name = 'wrappers',
    srcs = glob([
        "imported/*",
    ])
)

filegroup(
    name = 'compiler_files',
    srcs = [':wrappers',
       '@gcc-12-riscv64-toolchains//:compiler_files',
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
    ar_files = ":compiler_files",
    as_files = ":empty",
    compiler_files = ":compiler_files",
    dwp_files = ":empty",
    linker_files = ":compiler_files",
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
        "-Wall",
    ],
    compiler = "gcc",
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    cpu = "riscv64",
    # we really want the following to be constructed from $(output_base) or $(location ...)
    cxx_builtin_include_directories = [
       OUTPUT_BASE + "/external/gcc-12-riscv64-toolchains/sysroot/usr/include",
       OUTPUT_BASE + "/external/gcc-12-riscv64-toolchains/riscv64-unknown-linux-gnu/include/c++/12.2.0",
       OUTPUT_BASE + "/external/gcc-12-riscv64-toolchains/lib/gcc/riscv64-unknown-linux-gnu/12.2.0/include",
       OUTPUT_BASE + "/external/gcc-12-riscv64-toolchains/lib/gcc/riscv64-unknown-linux-gnu/12.2.0/include-fixed",
       ],
    cxx_flags = [
        "-std=c++20",
        "-fno-rtti",
        ],
    dbg_compile_flags = ["-g"],
    host_system_name = ":empty",
    link_flags = [],
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
        "ar": "imported/ar",
        "ld": "imported/riscv64-unknown-gnu-ld",
        "cpp": "imported/cpp",
        "gcc": "imported/gcc",
        "dwp": ":empty",
        "gcov": ":empty",
        "nm": "imported/nm",
        "objcopy": "imported/objcopy",
        "objdump": "imported/objdump",
        "strip": "imported/strip",
    },
    toolchain_identifier = "gcc-12-riscv64",
    unfiltered_compile_flags = [
        "-fno-canonical-system-headers",
        "-Wno-builtin-macro-redefined",
        "-D__DATE__=\"redacted\"",
        "-D__TIMESTAMP__=\"redacted\"",
        "-D__TIME__=\"redacted\"",
    ],
)

# x86_64 local

filegroup(
    name = "x86_64_compiler_deps",
    srcs = [],
)

toolchain(
    name = "x86_64_local_host",
    target_compatible_with = [
        ":x86_64",
    ],
    toolchain = ":cc-compiler-k8",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)

cc_toolchain(
    name = "cc-compiler-k8",
    toolchain_identifier = "local",
    toolchain_config = ":local_config",
    all_files = ":x86_64_compiler_deps",
    ar_files = ":x86_64_compiler_deps",
    as_files = ":x86_64_compiler_deps",
    compiler_files = ":x86_64_compiler_deps",
    dwp_files = ":empty",
    linker_files = ":x86_64_compiler_deps",
    objcopy_files = ":empty",
    strip_files = ":empty",
    supports_param_files = 1,
    module_map = None,
)
cc_toolchain_config(
    name = "local_config",
    cpu = "k8",
    compiler = "gcc",
    toolchain_identifier = "local",
    host_system_name = "local",
    target_system_name = "local",
    target_libc = "local",
    abi_version = "local",
    abi_libc_version = "local",
    cxx_builtin_include_directories = ["/usr/lib/gcc/x86_64-redhat-linux/13/include",
    "/usr/local/include",
    "/usr/include",
    "/usr/include/c++/13",
    "/usr/include/c++/13/x86_64-redhat-linux",
    "/usr/include/c++/13/backward"],
    tool_paths = {"ar": "/usr/bin/ar",
        "ld": "/usr/bin/ld",
        "llvm-cov": "None",
        "llvm-profdata": "None",
        "cpp": "/usr/bin/cpp",
        "gcc": "/usr/bin/gcc",
        "dwp": "/usr/bin/dwp",
        "gcov": "/usr/bin/gcov",
        "nm": "/usr/bin/nm",
        "objcopy": "/usr/bin/objcopy",
        "objdump": "/usr/bin/objdump",
        "strip": "/usr/bin/strip"},
    compile_flags = ["-fstack-protector",
    "-Wall",
    "-Wunused-but-set-parameter",
    "-Wno-free-nonheap-object",
    "-fno-omit-frame-pointer"],
    opt_compile_flags = ["-g0",
    "-O2",
    "-D_FORTIFY_SOURCE=1",
    "-DNDEBUG",
    "-ffunction-sections",
    "-fdata-sections"],
    dbg_compile_flags = ["-g"],
    cxx_flags = ["-std=c++0x"],
    link_flags = ["-fuse-ld=gold",
    "-Wl,-no-as-needed",
    "-Wl,-z,relro,-z,now",
    "-B/usr/bin",
    "-pass-exit-codes"],
    link_libs = ["-lstdc++",
                "-lm"],
    opt_link_flags = ["-Wl,--gc-sections"],
    unfiltered_compile_flags = ["-fno-canonical-system-headers",
    "-Wno-builtin-macro-redefined",
    "-D__DATE__=\"redacted\"",
    "-D__TIMESTAMP__=\"redacted\"",
    "-D__TIME__=\"redacted\""],
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    supports_start_end_lib = True,
)
