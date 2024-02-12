---
title: Instruction Patterns
linkTitle: Instruction Patterns
menu: {main: {weight: 10}}
weight: 10
---

{{% pageinfo %}}
Common instruction patterns one might see with vectorized code generation
{{% /pageinfo %}}

This page collects architecture-dependent gcc-14 *expansions*, where simple C sequences are translated into
optimized code.

Our baseline is a gcc-14 compiler with `-O2` optimization and a base machine architecture of `-march=rv64gc`.  That's a basic 64 bit RISCV
processor (or a `hart` core of that processor) with support for compressed instructions.

Variant machine architectures considered here are:

| march | description |
| ----- | ----------- |
| rv64gc | baseline   |
| rv64gcv | baseline + vector extension (dynamic vector length) |
| rv64gcv_zvl128b | baseline + vector (minimum 128 bit vectors) |
| rv64gcv_zvl512b | baseline + vector (minimum 512 bit vectors) |
| rv64gcv_zvl1024b | baseline + vector (minimum 1024 bit vectors) |
| rv64gc_xtheadbb | baseline + THead bit manipulation extension (no vector) | 

## Memory copy operations

>Note: memory copy operations require non-overlapping source
>      and destination.  memory move operations allow overlap
>      but are much more complicated and are not currently
>      optimized.

Optimizing compilers are good at turning simple memory copy operations into confusing - but fast - instruction sequences.
GCC can recognize memory copy operations as calls to `memcpy` or as structure assignments like `*a = *c`.

The current reference C file is:

```c
extern void *memcpy(void *__restrict dest, const void *__restrict src, __SIZE_TYPE__ n);
extern void *memmov(void *dest, const void *src, __SIZE_TYPE__ n);

/* invoke memcpy with dynamic size */
void cpymem_1 (void *a, void *b, __SIZE_TYPE__ l)
{
  memcpy (a, b, l);
}

/* invoke memcpy with known size and aligned pointers */
extern struct { __INT32_TYPE__ a[16]; } a_a, a_b;

void cpymem_2 ()
{
  memcpy (&a_a, &a_b, sizeof a_a);
}

typedef struct { char c[16]; } c16;
typedef struct { char c[32]; } c32;
typedef struct { short s; char c[30]; } s16;

/* copy fixed 128 bits of memory */
void cpymem_3 (c16 *a, c16* b)
{
  *a = *b;
}

/* copy fixed 256 bits of memory */
void cpymem_4 (c32 *a, c32* b)
{
  *a = *b;
}

/* copy fixed 256 bits of memory */
void cpymem_5 (s16 *a, s16* b)
{
  *a = *b;
}

/* memmov allows overlap - don't vectorize or inline */
void movmem_1(void *a, void *b, __SIZE_TYPE__ l)
{
  memmov (a, b, l);
}

```

### Baseline (no vector)

Ghidra 11 with the `isa_ext` branch decompiler gives us something simple after fixing the signature of the `memcpy`` thunk.

```c
void cpymem_1(void *param_1,void *param_2,size_t param_3)
{
  memcpy(param_1,param_2,param_3);
  return;
}
void cpymem_2(void)
{
  memcpy(&a_a,&a_b,0x40);
  return;
}
void cpymem_3(void *param_1,void *param_2)
{
  memcpy(param_1,param_2,0x10);
  return;
}
void cpymem_4(void *param_1,void *param_2)
{
  memcpy(param_1,param_2,0x20);
  return;
}
void cpymem_5(void *param_1,void *param_2)
{
  memcpy(param_1,param_2,0x20);
  return;
}
```

### rv64gcv - vector extensions

If the compiler knows the target hart can process vector extensions, but is not told
explicitly the size of each vector register, it optimizes all of these calls.  Ghidra 11 gives us
the following, with binutils' objdump instruction listings added as comments:

```c
long cpymem_1(long param_1,long param_2,long param_3)
{
  long lVar1;
  undefined auVar2 [256];
  do {
    lVar1 = vsetvli_e8m8tama(param_3);  // vsetvli a5,a2,e8,m8,ta,ma
    auVar2 = vle8_v(param_2);           // vle8.v  v8,(a1)
    param_3 = param_3 - lVar1;          // sub     a2,a2,a5
    vse8_v(auVar2,param_1);             // vse8.v  v8,(a0)
    param_2 = param_2 + lVar1;          // add     a1,a1,a5
    param_1 = param_1 + lVar1;          // add     a0,a0,a5
  } while (param_3 != 0);               // bnez    a2,8a8 <cpymem_1>
  return param_1;
}
void cpymem_2(void)
{
                                        // ld      a4,1922(a4) # 2040 <a_b@Base>
                                        // ld      a5,1938(a5) # 2058 <a_a@Base>
  undefined auVar1 [256];
  vsetivli(0x10,0xd3);                  // vsetivli        zero,16,e32,m8,ta,ma
  auVar1 = vle32_v(&a_b);               // vle32.v v8,(a4)
  vse32_v(auVar1,&a_a);                 // vse32.v v8,(a5)
  return;
}
void cpymem_3(undefined8 param_1,undefined8 param_2)
{
  undefined auVar1 [256];
  vsetivli(0x10,0xc0);                   // vsetivli        zero,16,e8,m1,ta,ma
  auVar1 = vle8_v(param_2);              // vle8.v  v1,(a1)
  vse8_v(auVar1,param_1);                // vse8.v  v1,(a0)
  return;
}
void cpymem_4(undefined8 param_1,undefined8 param_2)
{
  undefined auVar1 [256];                // li      a5,32
  vsetvli_e8m8tama(0x20);                // vsetvli        zero,a5,e8,m8,ta,ma
  auVar1 = vle8_v(param_2);              // vle8.v  v8,(a1)
  vse8_v(auVar1,param_1);                // vse8.v  v8,(a0)
  return;
}
void cpymem_5(undefined8 param_1,undefined8 param_2)
{
  undefined auVar1 [256];
  vsetivli(0x10,0xcb);                   // vsetivli        zero,16,e16,m8,ta,ma
  auVar1 = vle16_v(param_2);             // vle16.v v8,(a1)
  vse16_v(auVar1,param_1);               // vse16.v v8,(a0)
  return;
}
```

The variation in the `vset*` instructions is a bit puzzling.  This *may* be due to
alignment issues - trying to copy a `short int` into a misaligned odd address generates
an exception at the store instruction, so perhaps the vector optimization is supposed
to throw an exception there too.
