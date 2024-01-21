---
title: Notes
linkTitle: Notes
menu: {main: {weight: 50}}
weight: 50
---

{{% pageinfo %}}
Put unstructured comments here until we know what to do with them.
{{% /pageinfo %}}

## TODO

* Collect exemplars that fail Ghidra import into a common directory,
  including material that might help in creating a formal Ghidra issue
  or triaging future research and development initiatives.
* Update the `isa_ext` Ghidra branch to expand `vsetvli` arguments
* Determine why the `isa_ext` Ghidra branch fails to disassemble the `bext` instruction in `b-ext-64.o` and `b-ext.o`
* ~~Import THead objects through the THead language processor, not the default RISCV64.~~
* Determine why `semantics.o` won't disassemble
* Determine why `zvbc.o` won't disassemble
* Determine why `unknown.o` won't disassemble or reference where we found these instructions
* Normalize logger initialization to prevent duplicate logger messaging
* Clarify python scripts to show more of the directory context

## Existing scattered documentation to be consolidated here

```text
 3715 Oct 16 06:27 ./Roadmap.md
 5252 Nov 20 13:08 ./Sidebars.md
```

## Experiments

### how much Ghidra complexity does gcc-14 introduce in a full build?

Assume a vendor generates a new toolchain with multiple extensions enabled by default.  What fraction of the compiled functions would
contain extensions unrecognized by Ghidra 11.0?  Since THead has supplied most of the vendor-specific extensions known to binutils 2-41,
we'll use that as a reference.  The architecture name will be something like 

```text
-march=rv64gv_zba_zbb_zbc_zbkb_zbkc_zbkx_zvbc_xtheadba_xtheadbb_xtheadbs_xtheadcmo_xtheadcondmov_xtheadmac_xtheadfmemidx_xtheadmempair_xtheadsync
```

Add some C++ code to exercise libstdc++ ordered maps (based on red-black trees?), unordered maps (hash table based), and the Murmur hash function.

There are a few places where THead customized instructions are used.  The Murmur hash function uses vector load and store instructions to implement 8 byute unaligned
reads.  Bit manipulation extension instructions are not yet used.

Initial results suggest the largest complexity impact will be gcc rewriting of memory and structure copies with vector code.  This may be
especially true for hardware requiring aligned integers where alignment can not be guaranteed.