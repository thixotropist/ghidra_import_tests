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

# x86_64 on the local development computer
platform(
    name = "x86_64_userspace",
    constraint_values = [
        "//toolchains:x86_64",
    ],
)
