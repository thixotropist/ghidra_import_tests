"""
This Toolchain class includes everything needed for Bazel crosscompilation
except for the Bazel wrapper itself
"""

class Toolchain():
    """ 
    We would like at least four user process C and C++ toolchains:
    * a riscv64 toolchain matching the deployment instruction set, system root,
    *    and base library set.
    * a local host toolchain for checking basic C and C++ syntax or
    *    generating locally-executed tools
    * a riscv64 toolchain aligned with unreleased gcc, binutils, and libraries
    *    to get experience with newer features like riscv intrinsics and autovectorization

    Toolchain testing needs exemplars combining:
    * C and C++ sources
    * simple compile, compile and collect to a library, compile and link to an ELF executable
    * debug and optimized compilation
    * build for deployment on a RISC-V 64 bit CPU and for testing on an x86_64 CI server
    * various dependencies, such as a custom RISC-V libstdc++ and an imported Bazel Module
    *    like googletest or glog

    The biggest challenges in toolchain debugging tend to involve linking and loading, where
    `gcc` or `g++` implicitly invokes `collect2`, `ld`, `ar`, and various linker scripts.
    It is very hard to prove that these implicit dependencies are taken from the imported
    toolchain and not from the host linker environment.  The dynamic libraries (`.so`) needed
    for toolchain executables can be a similar headache.
    """

    # Bazel targets used to test the toolchain environment
    REFERENCE_C_PGM = '//riscv64/generated/userSpaceSamples:helloworld'
    REFERENCE_CPP_PGM = '//riscv64/generated/userSpaceSamples:helloworld++'

    # The default risc-v 64 bit platform, roughly tracking an SiFive SDK
    DEFAULT_RISCV64_PLATFORM = '//riscv64/generated/platforms:riscv_userspace'

    # A RISCV-64 platform with support for vector and other mainstream extensions.
    # This likely includes gcc-14 and binutils libraries not yet formally released
    VECTOR_RISCV64_PLATFORM = '//riscv64/generated/platforms:riscv_vector'

    # A RISCV-64 platform supporting vector and vendor-specific extensions
    VENDOR_EXTENSION_RISCV64_PLATFORM = '//riscv64/generated/platforms:riscv_custom'

    # An x86_64 platform
    DEFAULT_X86_64_PLATFORM = '//x86_64/generated/platforms:x86_64_default'

    # a bazel-generated platform representing the local development system
    LOCAL_HOST_PLATFORM = '@local_config_platform//:host'
