#! /usr/bin/bash

echo "Show RISCV64 platforms, cpu constraints, and available toolchains"
echo "Available platforms:"
bazel query 'kind(platform, riscv64/generated/platforms:*)'
echo "CPU constraints:"
bazel query 'kind(constraint_value, riscv64/generated/toolchains/riscv:*)'
echo "Registered Toolchain Configurations:"
bazel query 'kind(cc_toolchain_config, riscv64/generated/toolchains/riscv:*)'

