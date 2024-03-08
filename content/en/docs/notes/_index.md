---
title: Notes
linkTitle: Notes
weight: 100
---

{{% pageinfo %}}
Put unstructured comments here until we know what to do with them.
{{% /pageinfo %}}

## TODO

* [ ] Update the `isa_ext` Ghidra branch to expand `vsetvli` arguments
    * `vsetvli zero,zero,0xc5` ⇒ `vsetvli	zero,zero,e8,mf8,ta,ma`
    * `vsetvli zero,zero,0x18` ⇒ `vsetvli	zero,zero,e64,m1,tu,mu`
* [X] Determine why the `isa_ext` Ghidra branch fails to disassemble the `bext` instruction in `b-ext-64.o` and `b-ext.o`
    * that regression was do to an accidental typo
* [x] Determine why `zvbc.o` won't disassemble
    * These are compressed (16 bit) vector multiply instructions not currently defined in `isa_ext`
* [X] Determine why `unknown.o` won't disassemble or reference where we found these instructions
    * These instructions include `sfence``, `hinval_vvma`, `hinval_gvma`, `orc.b`, `cbo.clean`, `cbo.inval`, `cbo.flush`.
      `orc.b` is handled properly, the others are not implemented.
* [ ] Clarify python scripts to show more of the directory context

## Experiments

### how much Ghidra complexity does gcc-14 introduce in a full build?

Assume a vendor generates a new toolchain with multiple extensions enabled by default.  What fraction of the compiled functions would
contain extensions unrecognized by Ghidra 11.0?  Since THead has supplied most of the vendor-specific extensions known to binutils 2-41,
we'll use that as a reference.  The architecture name will be something like 

```text
-march=rv64gv_zba_zbb_zbc_zbkb_zbkc_zbkx_zvbc_xtheadba_xtheadbb_xtheadbs_xtheadcmo_xtheadcondmov_xtheadmac_xtheadfmemidx_xtheadmempair_xtheadsync
```

Add some C++ code to exercise libstdc++ ordered maps (based on red-black trees?), unordered maps (hash table based), and the Murmur hash function.

There are a few places where THead customized instructions are used.  The Murmur hash function uses vector load and store instructions to implement 8 byte unaligned
reads.  Bit manipulation extension instructions are not yet used.

Initial results suggest the largest complexity impact will be gcc rewriting of memory and structure copies with vector code.  This may be
especially true for hardware requiring aligned integers where alignment can not be guaranteed.