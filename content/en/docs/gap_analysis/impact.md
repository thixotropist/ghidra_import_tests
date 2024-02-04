---
title: Impact
linkTitle: Impact
weight: 20
---

{{% pageinfo %}}
What is the impact of this gap?
{{% /pageinfo %}}

## How

Ghidra's current limits in handling RISCV-64 vector instructions will impact users in phases, where the initial impacts are modest and fairly easy to deal
with while later impacts will take significant design work to address.

The most immediate impact involves Ghidra disassembly and decompilation failure when encountering unrecognized instructions.  The Fedora 39 exemplar kernel
contains several extension instructions that Ghidra 11 can't recognize.  These are limited in number and don't have a material impact on someone examining
RISCV kernel code.  The voice-to-text app whisper.cpp shows more serious limits - roughly one third of the app's instructions are unprocessed by Ghidra 11
because of vector and other extension instructions.

That impact can be addressed by simply defining the missing instructions, as in Ghidra's `isa_ext` experimental branch.  This will allow the disassembler and
decompiler to process all instructions in the app.  This is necessary but not sufficient, since many or most of the vector extension instructions do not have
a clean pcode representation.  Obvious calls to `memcpy` will be replaced with one of a half-dozen inline vector instruction sequences.  Simple or nested
loops will be 'vectorized' with fewer iterations but much more complex instruction opcode sequences.  Optimizing compilers can handle those complexities, while
Ghidra users searching for malware will have a harder time of it.

The general challenge for Ghidra is that of reconstructing the context from sequences of vector extension instructions.

## When

>Note: Some material comes as-is from https://www.reddit.com/r/RISCV

The first generally available 64 bit RISCV vector systems development kit has just become available (January 2024), based on the relatively modest
THead C908 core.  This SDK appears tuned for video processing, perhaps video surveilance applications aggregating multiple cameras into a common video feed.
We are probably several years from seeing server-class systems built on SiFive P870 cores, and fabricated on the fastest available fab lines.  Memory bandwidth
is poor at present, while energy efficiency is potentially better than x86_64 designs.

Judging from internet hype, we can expect to see RISCV vector code appearing in replacements of ARM systems (automotive and possibly cell phone) and as the extensible
basis of AI applications.  

* Cores announced
    * SiFive
        * [P670](https://www.sifive.com/cores/performance-p650-670) 2 x 128 bit vector units, up to 16 cores
        * [P870](https://www.sifive.com/cores/performance-p870-p870a) 2 x 128 bit vector units, vector crypto, up to 16 cores
    * Alibaba XuanTie THead
        * [C908](https://riscv.org/blog/2022/11/xuantie-c908-high-performance-risc-v-processor-catered-to-aiot-industry-chang-liu-alibaba-cloud/)
          with RVV 1.0 support, 128 bit VLEN; announced 2022
    * StarFive
        * [Starfive](https://www.starfivetech.com/en/site/riscv-core-ip) does not appear to offer a vector RISCV core
* SDKs available
    * [CanMV-K230](https://www.youyeetoo.com/products/canmv-k230-kendryte-k230-risc-v64-board?VariantsId=11596),
      dual C908 cores, triple video camera inputs, $40; one core supports RVV 1.0 at 1.6 GHz; 512 MB RAM; announced 2023
    * Sophgo [SG2380](https://forum.sophgo.com/t/about-the-sg2380-oasis-category/359) due Q3 2024 with 16 core SiFive P670
      and 8 core SiFiveX280

## Who is working this

January 2024 saw a flurry of open source toolchain and framework contributions from several sources.

* binutils contributors
    * multiple recent contributors from Alibaba, mostly in support of THead extensions
* gcc contributors
    * intel, alibaba, rivai (ref XCVsimd extension), embecosm, sifive, eswincomputing, ventanamicro, andestech all contributed to the riscv testsuite in the last two weeks.
* glibc contributions
    * some references to Alibaba riscv extensions
* ML framework contributors
    * riscv intrinsics appeared in whisper.cpp in November 2023, sync'd from [llama](https://github.com/ggerganov/llama.cpp/commit/79f34abddb72ac5ddbf118f3d87520b611a10a7d),
      originally contributed by https://pk.linkedin.com/in/ahmad-tameem

