---
title: ISA Extensions
linkTitle: ISA Extensions
weight: 10
---

{{% pageinfo %}}
Extensions to a processor family's Instruction Set Architecture add capability and complexity.
{{% /pageinfo %}}

The RISCV community has a rich set of extensions to the base Instruction Set Architecture.  That means a diverse set
of new binary import targets to test against.  This work-in-progress is collected in the `riscv64/toolchain/assemblySamples` directory.
The basic idea is to compare current Ghidra disassembly with current binutils `objdump` disassembly, using object files
assembled from the binutils `gas` testsuite.  For example:

* `riscv64/toolchain/assemblySamples/h-ext-64.S` was copied from the binutils gas testsuite.  It contains unit test instructions for
  hypervisor support extensions like `hfence.vvma` and `hlv.w`.
* `riscv64/exemplars/h-ext-64.o` is the object file produced by a *current snapshot* of the binutils 2-41 assembler.  The associated listing
  is `riscv64/exemplars/h-ext-64.list`.
* `riscv64/exemplars/h-ext-64.objdump` is the output from disassembling `riscv64/exemplars/h-ext-64.o` using the current snapshot of the binutils 2-41
  `objdump`.

So we want to open Ghidra, import `riscv64/exemplars/h-ext-64.o`, and compare the disassembly window to `riscv64/exemplars/h-ext-64.objdump`, then triage
any variances.

Some variances are trivial.  The `h-ext-64.S` tests include instructions that assemble into a single 4 byte sequence.  Disassembly will only give a single
instruction, perhaps the simplest one of the given aliases.

Other variances are harder - it looks like Ghidra expects to see an earlier and deprecated set of vector instructions than one currently approved set.

`riscv64/toolchain/assemblySamples/TODO.md` collects some of the variances noted so far.

One big question is what kind of pcode should Ghidra generate for some of these instructions - and how many Ghidra users will care about that pcode.
The short term answer is to treat extension instructions as pcode function calls.  The longer term answer may be to wait until GCC14 comes out with support for
vector extensions, then see what kind of C source is conventionally used when invoking those extensions.  The `memcpy` inline function from `libc` is a likely
place to find early use of vector instructions.

Also, what can we safely ignore for now?  The proposed vendor-specific T-Head extension instruction
[`th.l2cache.iall`](https://github.com/T-head-Semi/thead-extension-spec/blob/master/xtheadcmo/l2cache_iall.adoc) won't be seen by most Ghidra users.
On the other hand, the encoding rules published with those T-Head extensions look like a good example to follow.

The Fedora 39 kernel includes virtual machine cache management instructions that are not necessarily supported by binutils - they are 'assembled' with gcc macros
before reaching the binutils assembler.  We will ignore those instruction extensions for now, and only consider instruction extensions supported by binutils.

## Determining the ISA extensions required by a binary

Some newer compilers annotate executable binaries by adding the ISA extensions used during the build.

```console
$ /opt/riscvx/bin/riscv64-unknown-linux-gnu-readelf -A riscv64/exemplars/whisper_cpp_default
Attribute Section: riscv
File Attributes
  Tag_RISCV_stack_align: 16-bytes
  Tag_RISCV_arch: "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicsr2p0_zmmul1p0"

$ /opt/riscvx/bin/riscv64-unknown-linux-gnu-readelf -A riscv64/exemplars/whisper_cpp_vector
Attribute Section: riscv
File Attributes
  Tag_RISCV_stack_align: 16-bytes
  Tag_RISCV_arch: "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_v1p0_zicsr2p0_zifencei2p0_zmmul1p0_zve32f1p0_zve32x1p0_zve64d1p0_zve64f1p0_zve64x1p0_zvl128b1p0_zvl32b1p0_zvl64b1p0"
  Tag_RISCV_priv_spec: 1
  Tag_RISCV_priv_spec_minor: 11

$ /opt/riscvx/bin/riscv64-unknown-linux-gnu-readelf -A riscv64/exemplars/whisper_cpp_vendor
Attribute Section: riscv
File Attributes
  Tag_RISCV_stack_align: 16-bytes
  Tag_RISCV_arch: "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_v1p0_zicsr2p0_zifencei2p0_zmmul1p0_zba1p0_zbb1p0_zbc1p0_zbkb1p0_zbkc1p0_zbkx1p0_zvbc1p0_zve32f1p0_zve32x1p0_zve64d1p0_zve64f1p0_zve64x1p0_zvl128b1p0_zvl32b1p0_zvl64b1p0_xtheadba1p0_xtheadbb1p0_xtheadbs1p0_xtheadcmo1p0_xtheadcondmov1p0_xtheadfmemidx1p0_xtheadmac1p0_xtheadmempair1p0_xtheadsync1p0"
  Tag_RISCV_priv_spec: 1
  Tag_RISCV_priv_spec_minor: 11
```

If `Tag_RISCV_arch` contains the substring `v1p0`, then the associated binary was built assuming RV Vector 1.0 extension instructions are present on the executing CPU hardware thread.
