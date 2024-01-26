---
title: Analysis of the Speach Recognition System Whisper_cpp
weight: 10
---

{{% pageinfo %}}
Explore analysis of a machine learning application built with large language model techniques.  What Ghidra gaps does such an analysis reveal?
{{% /pageinfo %}}

How might we inspect a machine-learning application for malware? For example, suppose someone altered the automatic speach recognition library [whisper.cpp](https://github.com/ggerganov/whisper.cpp).  Would Ghidra be able to cope with the instruction set extensions used to accelerate ML inference engines?  What might be added to Ghidra to help the human analyst in this kind of inspection?

Components for this exercise:

* A Linux x86_64 Fedora 39 base system
* Ghidra 11.0 public
* Ghidra 11.1-DEV with the `isa_ext` branch for RISCV-64 support
* A stripped target binary `whisper_cpp_vendor` built with RISCV-64 gcc-14 toolchain and the whisper.cpp 1.5.4 release.
    * RISCV-64 vector and other approved extensions are enabled for this build
    * published binutils-2.41 vendor-specific extensions are enabled for this build
    * whisper library components are statically linked, while system libraries are dynamically linked
* Reference binaries `whisper_cpp_*` built locally with other RISCV-64 gcc toolchains
* Ghidra's BSIM binary similarities plugins and analytics

Questions to address:

* does the presence of vector and other ISA extensions in `whisper_cpp_vendor` materially hurt Ghidra 11.0 analysis?
* can BSIM analytics still find similarities between `whisper_cpp_vendor` and the non-vector build `whisper_cpp_default`
* are there recurring vector instruction patterns present in `whisper_cpp_vendor` that Ghidra users should be able to recognize?
* are there additional instructions or instruction-semantics that we should add to the `isa_ext` branch?
* if the vendor adds Link Time Optimization to their `whisper_cpp_vendor` build, does this materially hurt Ghidra 11.0 analysis?

There are a lot of variables in this exercise.  Some are important, most are not.

## Baseline Ghidra analysis

Starting with the baseline Ghidra 11.0, examine a locally built `whisper_cpp_default`, an ELF 64-bit LSB executable built with gcc-13.2.1.
Import and perform standard analyses to get these statistics:

* 186558 instructions recognized 
* text segment size 0x8678a
* 12 bad instruction errors, all of which appear to be the `fence.tso` instruction extension

Now examine `whisper_cpp_vendor` with the baseline Ghidra 11.0:

* 100521 instructions recognized
* text segment size 0xb93cc
* 4299 bad instruction errors

Examine `whisper_cpp_vendor` with the `isa_ext` branch of 11.1-DEV:

* 169813 instructions recognized
* text segment size 0xb93cc
* 17 bad instruction errors, all of which appear to be the `fence.tso` instruction extension

Next apply a manual correction to `whisper_cpp_vendor`, selecting the entire `.text` segment and
forcing disassembly, then clearing any unreachable 0x00 bytes.

* 190311 instructions recognized
* 17 bad instruction errors
* 4138 `vset*` instructions usually found at the start of vector code
* 946 `gather` instructions
* 3562 `custom` instructions

Finally, reset the 'language' of `whisper_cpp_vendor` to match the vendor (THead, for this exercise).

The 3562 custom instructions resolve to:

| Instruction | Count | Semantics |
| :---------- | ----: | :-------- |
| th.ext* | 151 | Sign extract and extend|
| th.ldd | 1719 | Load 2 doublewords |
| th.lwd | 10 | Load 2 words |
| th.sdd | 1033 | store 2 doublewords |
| th.swd | 16 | store 2 words |
| th.mula | 284 | Multiply-add  |
| th.muls | 67 | Multiply-subtract |
| th.mveqz | 127 | Move if == 0 |
| th.mvneqz | 154 | Move if != 0 |

This leads to some tentative next steps:

1. Adding `fence.tso` to Ghidra looks like a simple small win, and a perfect place to start.
2. The THead vendor-specific extensions look like simple peep-hole optimizations.  The semantics could
   easily be added to Ghidra as compositions of two original instruction semantics.  Slightly less than 2% of the total instructions are THead vendor customizations.
3. The baseline Ghidra 11.0 stalls out very quickly on the vector instructions, making an early switch
   to the `isa_ext` branch necessary.
4. The vector and scalar `gather` instructions are unexpectedly prevalent.  Understanding how to
   capture the semantics of the scalar `gather` instructions may be a good early step on the way to
   general semantic capture of the vector instructions.
5. Manual inspection and sampling of the 4138 `vset*` instruction blocks may reveal some key patterns to
   recognize first.

>Note: `fence.tso` is now recognized in the Ghidra 11.1-DEV branch `isa_ext`,
>      clearing the `bad instruction errors`.