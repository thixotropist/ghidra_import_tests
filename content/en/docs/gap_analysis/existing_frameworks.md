---
title: Existing Frameworks
linkTitle: Existing Frameworks
weight: 50
---

{{% pageinfo %}}
Which Ghidra frameworks might be extended to fill the gap?
{{% /pageinfo %}}

## Outline

* What can we add to sleigh `.sinc` files?
    * add all extension instructions
    * add translation of Elf file attributes into vendor-specific processor selection
    * flesh out extension mnemonics to convey vector context, especially `vset*` instructions
    * add comments or metadata that is accessible to the decompiler
* What can we add to pcode semantics?
    * gcc built-ins like __builtin_memcpy or popcount
    * cross platform vector notation
    * processor dependent decompiler plugins
* What can we add to disassembler
    * generalized instruction information on common use patterns
* What can we add to decompiler
    * reconstruct gcc RTL built-ins
* What plugins can we add?
    * reconstruct gcc RTL built-ins
* What external tools can we leverage?
    * generate .sinc updates based on objdump mnemonics
    * known source exemplar builds to correlate RTL expressions with instruction sequences
    * apply general ML translation to undo pcode expansion into vector instructions
