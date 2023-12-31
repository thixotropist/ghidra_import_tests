---
title: autovectorization
weight: 10
---

{{% pageinfo %}}
If a processor supports vector (aka SIMD) instructions, optimizing compilers will use them.  That means Ghidra may need to make sense of
the generated code.
{{% /pageinfo %}}

## Loop autovectorization

What happens when a gcc toolchain optimizes the following code?

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

The elements of the loop involve incremental indexing, narrowing from 16 bit to 8 bit elements,
and storage in a 1320 element vector.

The result depends on the compiler version and what kind of microarchitecture gcc-14 was told to compile for.

Compile and link this file with a variety of compiler versions, flags, and microarchitectures to see how well
Ghidra tracks toolchain evolution.  In each case the decompiler output is manually adjusted to relabel
variables like `s` and `i` and remove extraneous declarations.

### RISCV-64 gcc-13, no optimization, no vector extensions

```console
$ bazel build -s --platforms=//platforms:riscv_userspace  gcc_vectorization:narrowing_loop
...
```

Ghidra gives:

```c
  char s [1319];
 ...
  int i;
  ...
  for (i = 0; i < 0x527; i = i + 1) {
    s[i] = (char)i + '\x01';
  }
  ...
  printf(s);
```

The loop consists of 17 instructions and 60 bytes.  It is executed 1319 times

### RISCV-64 gcc-13, full optimization, no vector extensions

```console
bazel build -s --platforms=//platforms:riscv_userspace --copt="-O3" gcc_vectorization:narrowing_loop
```

Ghidra gives:

```c
  long i;
  char s_offset_by_1 [1320];
 
  i = 1;
  do {
    s_offset_by_1[i] = (char)i;
    i = i + 1;
  } while (i != 0x528);
  uStack_19 = 0;
  printf(s_offset_by_1 + 1);
```

The loop consists of 4 instructions and 14 bytes. It is executed 1319 times.

Note that Ghidra has reconstructed the target vector `s` a bit strangely, with the beginning
offset by one byte to help shorten the loop.

### RISCV-64 gcc-13, full optimization, with vector extensions

```console
bazel build -s --platforms=//platforms:riscv_userspace --copt="-O3"  gcc_vectorization:narrowing_loop_vector
```

The Ghidra import is essentially unchanged - updating the target architecture from `rv64igc` to `rv64igcv` makes no difference
when building with gcc-13.

### RISCV-64 gcc-14, no optimization, no vector extensions

```console
bazel build -s --platforms=//platforms:riscv_vector gcc_vectorization:narrowing_loop
```

The Ghidra import is essentially unchanged - updating gcc from gcc-13 to gcc-14 makes no difference without optimization.

### RISCV-64 gcc-14, full optimization, no vector extensions

```console
bazel build -s --platforms=//platforms:riscv_vector --copt="-O3" gcc_vectorization:narrowing_loop
```

The Ghidra import is essentially unchanged - updating gcc from gcc-13 to gcc-14 makes no difference - when using the default
target architecture without vector extensions.

### RISCV-64 gcc-14, full optimization, with vector extensions

Build with `-march=rv64gcv` to tell the compiler to assume the processor supports RISCV vector extensions.

```console
bazel build -s --platforms=//platforms:riscv_vector --copt="-O3"  gcc_vectorization:narrowing_loop_vector
```

```c
                    /* WARNING: Unimplemented instruction - Truncating control flow here */
  halt_unimplemented();
```

The disassembly window shows that the loop consists of 13 instructions and 46 bytes.
Many of these are vector extension instructions for which Ghidra 11.0 has no semantics.
Different RISCV processors will take a different number of iterations to finish the loop.
If the processor VLEN=128, then each vector register will hold 4 32 bit integers and the
loop will take 330 iterations.  If the processor VLEN=1024 then the loop will take 83 iterations.

Either way, Ghidra 11.0 will fail to decompile any such autovectorized loop, and fail to decompile
the remainder of any function which contains such an autovectorized loop.


### x86-64 gcc-14, full optimization, with sapphirerapids

>Note: Intel's Saphire Rapids includes high end server processors like the Xeon Max family.

```console
$ bazel build -s --platforms=//platforms:x86_64_default --copt="-O3" --copt="-march=sapphirerapids" gcc_vectorization:narrowing_loop
```

Ghidra 11.0 disassembler and decompiler fail immediately on hitting the first vector instruction `vpbroadcastd`, an older avx2 vector extension.

```c
    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
```

## builtin autovectorization

GCC can replace calls to some functions like `memcpy`, replacing those calls with inline - and potentially vectorized - instructions.

This source file shows different ways memcopy can be compiled.

```c
include "common.h"
#include <string.h>

int main() {
  const int N = 127;
  const uint32_t seed = 0xdeadbeef;
  srand(seed);

  // data gen
  double A[N];
  gen_rand_1d(A, N);

  // compute
  double copy[N];
  memcpy(copy, A, sizeof(A));
  
  // prevent optimization from removing result
  printf("%f\n", copy[N-1]);
}
```

Build this with:

```console
$ bazel build -s --platforms=//platforms:x86_64_default --copt="-O3" --copt="-march=sapphirerapids" gcc_vectorization:memcpy_sapphirerapids
```

Ghidra 11.0's disassembler and decompiler bail out when they reach the inline replacement for `memcpy` - gcc-14 has replaced the call with 
vector instructions like `vmovdqu64`, which is unrecognized by Ghidra.

```c
void main(void)

{
  undefined auStack_428 [1016];
  undefined8 uStack_30;
  
  uStack_30 = 0x4010ad;
  srand(0xdeadbeef);
  gen_rand_1d(auStack_428,0x7f);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
```