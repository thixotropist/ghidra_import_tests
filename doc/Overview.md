# Overview

This project collects files that may stress - in a good way - Ghidra's import capabilities.  Others are doing a great job extending Ghidra's ability to import
and recognize C++ structures and classes, so we will focus on lower level objects
like instruction sets and relocation codes.  The primary CPU family will be based on
the RISCV-64 processor.  This processor is relatively new and easily modified, so
it will likely show lots of new features early.  Not all of these new features will
make it into common use or arenas in which Ghidra is necessary, so we don't really
know how much effort is worth spending on any given feature.

The initial scope is limited to RISCV 64 bit processors capable of running a full
linux network stack.  We won't be looking to collect importable objects created
for 32 bit RISCV microcontrollers.

We will collect sample object files - exemplars - from current open source projects
that stress some aspect of Ghidra's import capabilities, then attempt to evalute the complexity of extending those import capabilities.

The current set of exemplars includes the following.

## Fedora and Ubuntu disk images

Both Fedora and Ubuntu provide full RISCV-64 disk images suitable for running under
kvm and qemu emulators.  Breaking these into components gives us several classes of
exemplars stressing Ghidra's import subsystem.

* The kernels include RISCV hypervisor instruction extensions that are not recognized
  by Ghidra.  These are relatively few, but sufficient to break some decompilation of functions within kernel binaries.
* Kernel modules show a broad range of RISCV relocation codes that were not supported
  within Ghidra prior to this project.  Most of these are now supported.

## Binutils Instruction Set Extensions

RISCV processors support many different instruction set extensions.  Many of these
are supported by binutils 2-41, with sample assembly code present in the binutils 2-41 `gas` assembler's testsuite.  We can import these assembly source files, assemble them with a binutils 2-41 toolchain, then import them into Ghidra.
RISCV Vector instruction extensions look like the single largest class of instructions needing Ghidra support by 2024.  RISCV vendor specific instructions
defined by Alibaba or others may need support sometime later.

## GCC-14 Vector Intrinsics and Autovectorization

GCC-14, due sometime mid-2024, includes a huge number of RISCV vector builtin intrinsic functions.
The full set of intrinsics is defined in https://github.com/riscv-non-isa/rvv-intrinsic-doc, and far beyond what Ghidra can recognize anytime soon.
We will start with the examples provided by that site:

* rvv_memcpy.c  - a vector replacement for libc's memcpy
* rvv_strncpy.c - a vector replacement for libc's strncpy
* rvv index.c   - vector sum:  `a[i] = b[i] + (double)i * c[i]`
* rvv_matmul.c  - floating point matrix multiply
* rvv_reduce.c  - Masked vector sum: `if (a[i] != 42.0)  s += a[i] * b[i]`

For each of these examples we compile with a minimal gcc-14 riscv toolchain
into exemplar files, then import into Ghidra.  The next step for Ghidra is to
generate simplistic pcode for intrinsic functions like:

* `__riscv_vsetvl_e8m8(n)`       - set vector element size 8 bits
* `__riscv_vle8_v_u8m8(src, vl)` - load a vector of 8 bit bytes
* `__riscv_vse8_v_u8m8(dst, vec_src, vl)` - store a vector of 8 bit bytes
* `__riscv_vmseq_vx_u8m1_b8(vec_src, 0, vl)` - search a vector for null bytes

## openssl crypto extensions

The openssl source should support common cryptographic operations in at least
three different RISCV configurations:

* RISCV-64 with no cryptographic extension instructions
  * this code appears to be generated with a perl script `aes-riscv64.pl`
* RISCV-64 with scalar cryptographic extension instructions
  * this code appears to be generated with a perl script `aes-riscv64-zkn.pl`
    if the target processor architecture includes the zkne extension.
    This extension implements [RISCV AES extensions](https://github.com/riscv/riscv-crypto/blob/main/doc/scalar/riscv-crypto-scalar-zkne.adoc)
* RISCV-64 with vector cryptographic extension instructions
  * this code is (apparently) not yet present in the main development branch of openssl.

  