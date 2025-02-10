package(default_visibility = ["//visibility:public"])

# riscv_userspace using a stable gcc environment
platform(
    name = "riscv64_default",
    constraint_values = [
        "//riscv64/generated/toolchains/riscv:riscv64",
    ],
)

# a riscv userspace platform with a CPU supporting vector instructions.
# In gcc machine architecture terms, a march=rv64gcv
platform(
    name = "riscv64_rva23",
    constraint_values = [
        "//riscv64/generated/toolchains/riscv:riscv64-rva23-supported",
    ],
)

platform(
    name = "riscv64_thead",
    constraint_values = [
        "//riscv64/generated/toolchains/riscv:riscv64-thead-supported",
    ],
)

# x86_64 variant of "riscv_vector"
platform(
    name = "x86_64",
    constraint_values = [
        "//riscv/generated/toolchains:x86_64",
    ],
)
