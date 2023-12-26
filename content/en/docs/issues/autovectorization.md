---
title: autovectorization
weight: 10
---

{{% pageinfo %}}
If a processor supports vector (aka SIMD) instructions, optimizing compilers will use them.  That means Ghidra may need to make sense of
the generated code.
{{% /pageinfo %}}

What happens when the gcc-14 RISCV toolchain optimizes the following code for a processor with vector extensions?


```c
#include <stdio.h>
int main(int argc, char** argv){
    const int N = 1320;
    char s[N];
    for (int i = 0; i < N - 1; ++i)
        s[i] = i + 1;
    s[N - 1] = '\0';
    printf(s);
}
```

This involves a simple loop filling a character array with integers.  It isn't a well formed C string,
so the `printf` statement is just there to keep the character array from being optimized away.

The elements of the loop involve incremental indexing, narrowing from 32 bit to 8 bit elements,
and storage in a 1320 element vector.


Ghidra's 11.0 release decompiles this into:

```text
/* WARNING: Control flow encountered unimplemented instructions */

void main(void)

{
  gp = &__global_pointer$;
                    /* WARNING: Unimplemented instruction - Truncating control flow here */
  halt_unimplemented();
}
```

Ghidra 11.0 fails because its vector extensions lack any pcode semantics, and are intended for the
deprecated and unratified 0.7 vector extension documents.

Try the import again with the `isa_ext` experimental branch of Ghidra.  This branch updates vector extensions to
the ratified 1.0 release and includes placeholder pcode semantics.

```text
undefined8 main(void)

{
  undefined auVar1 [64];
  undefined8 uVar2;
  undefined (*pauVar3) [64];
  long lVar4;
  long lVar5;
  undefined auVar6 [256];
  undefined auVar7 [256];
  char local_540 [1319];
  undefined uStack_19;
  
  gp = &__global_pointer$;
  pauVar3 = (undefined (*) [64])local_540;
  lVar4 = 0x527;
  vsetvli_e32m1tama(0);
  auVar7 = vid_v();
  do {
    lVar5 = vsetvli(lVar4,0xcf);
    auVar6 = vmv1r_v(auVar7);
    lVar4 = lVar4 - lVar5;
    auVar6 = vncvt_xxw(auVar6);
    vsetvli(0,0xc6);
    auVar6 = vncvt_xxw(auVar6);
    auVar6 = vadd_vi(auVar6,1);
    auVar1 = vse8_v(auVar6);
    *pauVar3 = auVar1;
    uVar2 = vsetvli_e32m1tama(0);
    pauVar3 = (undefined (*) [64])(*pauVar3 + lVar5);
    auVar6 = vmv_v_x(lVar5);
    auVar7 = vadd_vv(auVar7,auVar6);
  } while (lVar4 != 0);
  uStack_19 = 0;
  printf(local_540,uVar2);
  return 0;
}
```

That Ghidra branch decompiles, but the decompilation listing only resembles the C source code if you are familiar with RISCV vector extension instructions.

Repeat the example, this time building with a gcc-13 toolchain.  Ghidra 11.0 does a fine job of decompiling this.

```c
undefined8 main(void)
{
  long lVar1;
  char acStack_541 [1320];
  undefined uStack_19;
    gp = &__global_pointer$;
  lVar1 = 1;
  do {
    acStack_541[lVar1] = (char)lVar1;
    lVar1 = lVar1 + 1;
  } while (lVar1 != 0x528);
  uStack_19 = 0;
  printf(acStack_541 + 1);
  return 0;
}
```

## understanding the vector instructions

>See the RISCV [vector spec](https://github.com/riscv/riscv-v-spec/blob/master/v-spec.adoc) for more information

* `vsetvli_e32m1tama(0)` - sets the vector context to expect 32 bit vectors with tail agnostic and mask agnostic processing
* `vid_v()` - The vid.v instruction writes each element’s index to the destination vector register group, from 0 to vl-1
* `vmv1r_v` - copy all elements of one vector register to another vector register
* `vncvt_xxw`  - narrow the elements of a vector register by half, e.g. 32 bits to 16, or 16 to 8.
* `vadd_vi` - add an immediate integer to a vector
* `vse8_v` - 8 bit unit stride store
* `vmv_v_x` - move a scalar value into all elements of a vector
* `vadd_vv` - add two vectors

If this binary executes on a processor with vectors of 256 bits, the 32 bit vector elements are processed 8 at a time instead of 1 at a time.
If we changed `for (int i = 0; i < N - 1; ++i)` into `for (unsigned short i = 0; i < N - 1; ++i)` we would likely get 16 elements processed at each loop iteration.

Note that the binary code is the same no matter what the vector register length may be.  If the processor had 512 bit vectors, it would handle twice as many
elements per loop iteration.

What would we like Ghidra's decompiler to do with this kind of input?

* A minimal solution would add a line of descriptive text to every vector instruction definition, which would be passed into the decompiler to be displayed
  as a comment.
* A wildly optimistic solution would treat the loop the same way a processor with an infinite vector size would treat it, rendering the loop as python - 
    ```python
    [0xff & (x+1) for x in range(0,1320)]
    ```
