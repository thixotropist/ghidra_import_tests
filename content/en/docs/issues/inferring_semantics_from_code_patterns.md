---
title: inferring semantics from code patterns
weight: 10
---

{{% pageinfo %}}
How can we do a better job of recognizing semantic patterns in
optimized code?  Instruction set extensions make that more challenging.
{{% /pageinfo %}}

Ghidra users want to understand the intent of binary code. The semantics
and intent of the `memcpy(dest,src,nbytes)` operation are pretty clear.
If the compiler converts this into a call to a named external function,
that's easy to recognize.  If it converts it into a simple inline loop of load and
store instructions, that should be recognizable too.

Optimizing compilers like gcc can generate many different instruction sequences from
a simple concept like `memcpy` or `strnlen`, especially if the processor for which the code is intended
supports advanced vector or bit manipulation instructions. We can examine the compiler
testsuite to see what those patterns can be, enabling either human or machine translation of
those sequences into the higher level semantics of memory movement or finding the first null
byte in a string.

Gcc semantics recognizes memory copy operations via the operation `cpymem`.  Calls to
the standard library `memcpy` and various kinds of struct copies are translated into this RTL (Register Transfer Logic)
`cpymem` token.  The processor-specific gcc backend then expands `cpymem` into a half-dozen or so instruction patterns,
depending on size, alignment, and instruction set extensions of the target processor.

In the ideal world, Ghidra would recognize all of those RTL operations as pcode operations, and further recognize
all of the common back end expansions for all processor variants.  It might rewrite the decompiler window or simply
add comments indicating a likely `cpymem` pcode expansion.

It's enough for now to show how to gather the more common patterns to help human Ghidra operators untangle these
optimizations and understand the simpler semantics they encode.

>Note: This example uses RISCV vector optimization - many other optimizations are supported by gcc too.

## Patterns in gcc vectorization source code

Maybe the best reference on gcc vectorization is the gcc source code itself.

* What intrinsics are likely to be replaced with vector code?
* What patterns of vector assembly instructions are likely to be generated?
* How does the gcc test suite search for those patterns to verify intrinsic replacement is correct?

Start with:

* `gcc/config/riscv/riscv-vector-builtins.cc`
* `gcc/config/riscv/riscv-vector-strings.cc`
* `gcc/config/riscv/autovec.md`
* `gcc/config/riscv/riscv-string.cc`

Ghidra semantics use `pcode` operations.  GCC uses something similar in RTL (Register Transfer Language).  These
are described in `gcc/doc/md.texi`.  These include:

* `cpymem`
* `setmem`
* `strlen`
* `rawmemchr`
* `cmpstrn`
* `cmpstr`

The `cpymem` op covers inline calls to memcpy and structure copies.  Trace this out:

`riscv.md`:

```lisp
(define_expand "cpymem<mode>"
  [(parallel [(set (match_operand:BLK 0 "general_operand")
                   (match_operand:BLK 1 "general_operand"))
              (use (match_operand:P 2 ""))
              (use (match_operand:SI 3 "const_int_operand"))])]
  ""
{
  if (riscv_expand_block_move (operands[0], operands[1], operands[2]))
    DONE;
  else
    FAIL;
})
```

`riscv_expand_block_move` is also mentioned in `riscv-protos.h` and `riscv-string.cc`.

Look into `riscv-string.cc`:

```c
/* This function delegates block-move expansion to either the vector
   implementation or the scalar one.  Return TRUE if successful or FALSE
   otherwise.  */

bool
riscv_expand_block_move (rtx dest, rtx src, rtx length)
{
  if (TARGET_VECTOR && stringop_strategy & STRATEGY_VECTOR)
    {
      bool ok = riscv_vector::expand_block_move (dest, src, length);
      if (ok)
        return true;
    }

  if (stringop_strategy & STRATEGY_SCALAR)
    return riscv_expand_block_move_scalar (dest, src, length);

  return false;
...
}
...
* --- Vector expanders --- */

namespace riscv_vector {

/* Used by cpymemsi in riscv.md .  */

bool
expand_block_move (rtx dst_in, rtx src_in, rtx length_in)
{
  /*
    memcpy:
        mv a3, a0                       # Copy destination
    loop:
        vsetvli t0, a2, e8, m8, ta, ma  # Vectors of 8b
        vle8.v v0, (a1)                 # Load bytes
        add a1, a1, t0                  # Bump pointer
        sub a2, a2, t0                  # Decrement count
        vse8.v v0, (a3)                 # Store bytes
        add a3, a3, t0                  # Bump pointer
        bnez a2, loop                   # Any more?
        ret                             # Return
 */
}
}
```

Note that the riscv assembly instructions in the comment are just an example, and that the C++ implementation
handles many different variants.  The `ret` instruction is not part of the expansion, just copied into the source
code from the testsuite.

The testsuite (`gcc/testsuite/gcc.target/riscv`) shows which variants are common enough to test against.

### a minimalist call to memcpy

```c
void f1 (void *a, void *b, __SIZE_TYPE__ l)
{
  memcpy (a, b, l);
}
```

```text
** f1:
XX      \.L\d+: # local label is ignored
**      vsetvli\s+[ta][0-7],a2,e8,m8,ta,ma
**      vle8\.v\s+v\d+,0\(a1\)
**      vse8\.v\s+v\d+,0\(a0\)
**      add\s+a1,a1,[ta][0-7]
**      add\s+a0,a0,[ta][0-7]
**      sub\s+a2,a2,[ta][0-7]
**      bne\s+a2,zero,\.L\d+
**      ret
*/
```

### a typed call to memcpy

```c
void f2 (__INT32_TYPE__* a, __INT32_TYPE__* b, int l)
{
  memcpy (a, b, l);
}
```

Additional type information doesn't appear to affect the inline code

```text
** f2:
XX      \.L\d+: # local label is ignored
**      vsetvli\s+[ta][0-7],a2,e8,m8,ta,ma
**      vle8\.v\s+v\d+,0\(a1\)
**      vse8\.v\s+v\d+,0\(a0\)
**      add\s+a1,a1,[ta][0-7]
**      add\s+a0,a0,[ta][0-7]
**      sub\s+a2,a2,[ta][0-7]
**      bne\s+a2,zero,\.L\d+
**      ret

```

### memcpy with aligned elements and known size

In this case arguments are aligned and 512 bytes in length.

```c
extern struct { __INT32_TYPE__ a[16]; } a_a, a_b;
void f3 ()
{
  memcpy (&a_a, &a_b, sizeof a_a);
}
```

The generated sequence varies depending on how much the compiler knows about the target architecture.

```text
** f3: { target { { any-opts "-mcmodel=medlow" } && { no-opts "-march=rv64gcv_zvl512b" "-march=rv64gcv_zvl1024b" "--param=riscv-autovec-lmul=dynamic" "--param=riscv-autovec-lmul=m2" "--param=riscv-autovec-lmul=m4" "-
-param=riscv-autovec-lmul=m8" "--param=riscv-autovec-preference=fixed-vlmax" } } }
**        lui\s+[ta][0-7],%hi\(a_a\)
**        addi\s+[ta][0-7],[ta][0-7],%lo\(a_a\)
**        lui\s+[ta][0-7],%hi\(a_b\)
**        addi\s+a4,[ta][0-7],%lo\(a_b\)
**        vsetivli\s+zero,16,e32,m8,ta,ma
**        vle32.v\s+v\d+,0\([ta][0-7]\)
**        vse32\.v\s+v\d+,0\([ta][0-7]\)
**        ret

f3: { target { { any-opts "-mcmodel=medlow --param=riscv-autovec-preference=fixed-vlmax" "-mcmodel=medlow -march=rv64gcv_zvl512b --param=riscv-autovec-preference=fixed-vlmax" } && { no-opts "-march=rv64gcv_zvl1024b" } } }
**        lui\s+[ta][0-7],%hi\(a_a\)
**        lui\s+[ta][0-7],%hi\(a_b\)
**        addi\s+[ta][0-7],[ta][0-7],%lo\(a_a\)
**        addi\s+a4,[ta][0-7],%lo\(a_b\)
**        vl(1|4|2)re32\.v\s+v\d+,0\([ta][0-7]\)
**        vs(1|4|2)r\.v\s+v\d+,0\([ta][0-7]\)
**        ret

** f3: { target { { any-opts "-mcmodel=medlow -march=rv64gcv_zvl1024b" "-mcmodel=medlow -march=rv64gcv_zvl512b" } && { no-opts "--param=riscv-autovec-preference=fixed-vlmax" } } }
**        lui\s+[ta][0-7],%hi\(a_a\)
**        lui\s+[ta][0-7],%hi\(a_b\)
**        addi\s+a4,[ta][0-7],%lo\(a_b\)
**        vsetivli\s+zero,16,e32,(m1|m4|mf2),ta,ma
**        vle32.v\s+v\d+,0\([ta][0-7]\)
**        addi\s+[ta][0-7],[ta][0-7],%lo\(a_a\)
**        vse32\.v\s+v\d+,0\([ta][0-7]\)
**        ret

** f3: { target { { any-opts "-mcmodel=medany" } && { no-opts "-march=rv64gcv_zvl512b" "-march=rv64gcv_zvl256b" "-march=rv64gcv_zvl1024b" "--param=riscv-autovec-lmul=dynamic" "--param=riscv-autovec-lmul=m8" "--param=riscv-autovec-lmul=m4" "--param=riscv-autovec-preference=fixed-vlmax" } } }
**        lla\s+[ta][0-7],a_a
**        lla\s+[ta][0-7],a_b
**        vsetivli\s+zero,16,e32,m8,ta,ma
**        vle32.v\s+v\d+,0\([ta][0-7]\)
**        vse32\.v\s+v\d+,0\([ta][0-7]\)

** f3: { target { { any-opts "-mcmodel=medany"  } && { no-opts "-march=rv64gcv_zvl512b" "-march=rv64gcv_zvl256b" "-march=rv64gcv" "-march=rv64gc_zve64d" "-march=rv64gc_zve32f" } } }
**        lla\s+[ta][0-7],a_b
**        vsetivli\s+zero,16,e32,m(f2|1|4),ta,ma
**        vle32.v\s+v\d+,0\([ta][0-7]\)
**        lla\s+[ta][0-7],a_a
**        vse32\.v\s+v\d+,0\([ta][0-7]\)
**        ret
*/

** f3: { target { { any-opts "-mcmodel=medany --param=riscv-autovec-preference=fixed-vlmax" } && { no-opts "-march=rv64gcv_zvl1024b" } } }
**        lla\s+[ta][0-7],a_a
**        lla\s+[ta][0-7],a_b
**        vl(1|2|4)re32\.v\s+v\d+,0\([ta][0-7]\)
**        vs(1|2|4)r\.v\s+v\d+,0\([ta][0-7]\)
**        ret
```