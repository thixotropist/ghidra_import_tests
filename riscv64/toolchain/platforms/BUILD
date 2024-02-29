package(default_visibility = ["//visibility:public"])

# riscv_userspace using a stable gcc environment
platform(
    name = "riscv_userspace",
    constraint_values = [
        "//toolchains:riscv64",
    ],
)

# a riscv userspace platform with a CPU supporting vector instructions.
# In gcc machine architecture terms, a march=rv64gcv
platform(
    name = "riscv_vector",
    constraint_values = [
        "//toolchains:riscv64-v",
    ],
)

platform(
    name = "riscv_custom",
    constraint_values = [
        "//toolchains:riscv64-c",
    ],
)

# riscv platform for toolchain debugging, using a local file system toolchain
platform(
    name = "riscv_local",
    constraint_values = [
        "//toolchains:riscv64-l",
    ],
)

# x86_64 variant of "riscv_vector"
platform(
    name = "x86_64",
    constraint_values = [
        "//toolchains:x86_64",
    ],
)
