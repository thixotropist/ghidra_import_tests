---
title: Whisper_cpp
weight: 10
---

{{% pageinfo %}}
Explore analysis of a machine learning application built with large language model techniques.  What Ghidra gaps does such an analysis reveal?
{{% /pageinfo %}}

How might we inspect a machine-learning application for malware? For example, suppose someone altered the automatic speech recognition library [whisper.cpp](https://github.com/ggerganov/whisper.cpp).  Would Ghidra be able to cope with the instruction set extensions used to accelerate ML inference engines?  What might be added to Ghidra to help the human analyst in this kind of inspection?

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

Now examine `whisper_cpp_vendor` (built with gcc 14 rather than gcc 13) with the baseline Ghidra 11.0:

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
* 4138 `vset*` instructions usually found in vector code
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
4. The vector `gather` instructions are unexpectedly prevalent.  
5. Manual inspection and sampling of the 4138 `vset*` instruction blocks may reveal some key patterns to
   recognize first.

>Note: `fence.tso` is now recognized in the Ghidra 11.1-DEV branch `isa_ext`,
>      clearing the `bad instruction errors`.

##  A top-down assessment

At the highest level, what features of `whisper.cpp` generate vector instructions?

* There are about 400 invocations of RISCV vector intrinsic within `ggml-quants.c`.  In these cases the developer
  has explicitly managed the vectorization.
* There are an unknown number of automatic loop vectorizations, where gcc-14 has replaced simple scalar loops with
  vector-based loops.  This vectorization will generally reduce the number of loop iterations, but may not always reduce
  the number of instructions executed.
* Gcc expansions of `memcpy` or structure copies into vector load-store loops.

Much of `whisper.cpp` involves vector, matrix, or tensor math using `ggml` math functions.  This is also where most
of the explicit RISCV vector intrinsic C functions appear, and likely the code the developer believes is most in need
of vector performance enhancements.

### Example: dot product

`ggml_vec_dot_f32(n, sum, x, y)` generates the vector dot product of two vectors x and y of length n with the result
stored to `*sum`.  In the absence of vector or SIMD support the source code is:

```c
// scalar
    float s;
    double sumf = 0.0;
    for (int i = 0; i < n; ++i) {
        sumf += (double)(x[i]*y[i]);
    }
   *s = sumf;
```

GCC-14 will autovectorize this into something Ghidra decompiles like this (comments added after `//`):

```c
void ggml_vec_dot_f32(long n,float *s,float *x,float *y)

{
  long step;
  double dVar1;
  undefined auVar2 [256];
  undefined in_v2 [256];
  undefined auVar3 [256];
  
  gp = &__global_pointer$;
  if (0 < n) {
    vsetvli_e64m1tama(0);
    vmv_v_i(in_v2,0);                  // v2 = 0
    do {
      step = vsetvli(n,0x97);          // vsetvli a5,a0,e32,mf2,tu,ma
      n = n - step;
      auVar3 = vle32_v(x);             // v3 = *x (slice of size step)
      auVar2 = vle32_v(y);             // v1 = *y (slice of size step)
      x = (float *)sh2add(step,x);      // x = x + step
      auVar2 = vfmul_vv(auVar2,auVar3); // v1 = v1 * v3
      y = (float *)sh2add(step,y);      // y = y + step
      in_v2 = vfwadd_wv(in_v2,auVar2);  // v2 = v1 + v2
    } while (n != 0);
    vsetvli_e64m1tama(0);
    auVar2 = vfmv_sf(0);                 // v1[0] = 0
    auVar2 = vfredusum_vs(in_v2,auVar2); // v1[0] = sum(v2)
    dVar1 = (double)vfmv_fs(auVar2);     // dvar1 = v1[0]
    *s = (float)dVar1;
    return;
  }
  *s = 0.0;
  return;
}
```

Inspecting this disassembly and decompilation suggests several top down issues:

* The semantics for `shadd2` are simple and should be explicit `sh2add(a, b) = a>>2 + b`
    * This is now implemented in Ghidra 11.1-DEV isa_ext.
* The `vsetvli(n,0x97)` instruction should be expanded to show semantics as `vsetvli_e32m2ftuma`
    * Running the binary through a RISCV objdump program gives us this formal expansion.  This instruction
      says that the selected element width is 32 bits with a LMUL multiplication factor of 1/2.  This means that only
      half of the vector register is used to allow for 64 bit arithmetic output.
    * This is now implemented in Ghidra 11.1-DEV isa_ext.
* The semantics for vector results need clarification
* The loop accumulates 64 bit double values with 32 bit input values.  If the vector length is 256 bits, that means
  the step size is 4 not 8
* A capability to generate processor-specific inline hints or comments in the decompiler may be useful, especially if
  there were a typographic way to distinguish vector and scalar objects.
* If vector registers were infinitely long the loop might become `v2 = x * y` and the reduction `dvar1 = reduce(+, v2)`

The path forward may be to manually analyze several examples from `whisper.cpp`, extending and revising Ghidra's semantics
and decompiler to add a bit of clarity each time.

### Example: auto-vectorization makes the simple complicated

Autovectorization can generate complicated code when the compiler has no knowledge of the number of elements in
a vector or the number of elements that can fit within single vector register.

A good example is from:

```c
ggml_tensor * ggml_new_tensor_impl(
        struct ggml_context * ctx,
        enum   ggml_type      type,
        int                   n_dims,
        const int64_t       * ne,
        struct ggml_tensor  * view_src,
        size_t                view_offs) {
...
         size_t data_size = ggml_row_size(type, ne[0]);
         for (int i = 1; i < n_dims; i++) {
            data_size *= ne[i];
         }
}
```

The `ne` vector typically has up to 4 elements, so this loop will be executed at most once.  The compiler doesn't know this so it
autovectorizes the loop into something more complex:

```c
undefined4 * ggml_new_tensor(ggml_context *ctx,undefined8 type,long ndims,int64_t *ne)

{
...
  data_size = ggml_row_size(type,*ne);              // get the first dimension ne[0]
  lVar6 = 1;
  if (1 < ndims) {
    uVar2 = (int)ndims - 1;
    if (1 < (int)ndims - 2U) {                      // if ndims > 3 process two at a time
      piVar7 = ne + 1;                              // starting with ne[1] and ne[2]
      piVar4 = piVar7 + (long)(int)(uVar2 >> 1) * 2;
      vsetivli_e64m1tamu(2);                        //vector length = 2, 64 bit element, tail agnostic mask unchanged
      vmv_v_i(in_v1,1);                             // v1 = (1,1)
      do {
        auVar10 = vle64_v(piVar7);
        piVar7 = piVar7 + 2;
        in_v1 = vmul_vv(in_v1,auVar10);              // v1 = v1 * ne[slice]
      } while (piVar4 != piVar7);
      auVar10 = vid_v();                             // v2 = (0,1)
      vmv_v_i(in_v4,0);                              // v4 = (0,0)
      auVar11 = vadd_vi(auVar10,1);                  // v2 = v2 + 1 = (1,2)
      auVar10 = vmsgtu_vi(auVar11,1);                // v0 = (v2 > 1) = (0, 1)
      vrgather_vv(in_v1,auVar11);                    // v3 = gather(v1, v2) => v3=v1[v2] = (v1[1], 0)
      auVar11 = vadd_vi(auVar11,0xfffffffffffffffe); // v2 = v2 - 2 = (-1,0)
      auVar10 = vrgather_vv(in_v4,auVar11,auVar10);  // v3 = gather_masked(v4,v2,v0.t) = (v3[0], v4[0])
      auVar10 = vmul_vv(auVar10,in_v1);              // v3 = v3 * v1
      vmv_x_s(in_v14,auVar10);                       // a4 = v3[0]
      data_size = data_size * (long)piVar4;          // data_size = data_size * a4
      if ((uVar2 & 1) == 0) goto LAB_00074a80;
      lVar6 = (long)(int)((uVar2 & 0xfffffffe) + 1);
    }
    plVar5 = (long *)sh3add(lVar6,ne);               // multiply by one or two 
    data_size = data_size * *plVar5;                 // 
    if ((int)lVar6 + 1 < ndims) {
      data_size = data_size * plVar5[1];
    }
  }
...
}
```

That's a very confusing way to multiply at most four integers.  If ne has 1, 2, or 3 elements then no vector instructions are processed at all.
If it has 4 elements then the first and last one or two are handled with scalar math while pairs of elements are accumulated in the loop.
The gather instructions are used together to generate a mask and then multiply the two elements of vector v1, leaving the result in the first
element slot of vector v4.

This particular loop vectorization is likely to change a lot in future releases.  The performance impact is negligible either way.  The analyst may
look at code like this and decide to ignore the ndims>3 case along with *all* of the vector instructions used within it.  Alternatively, we could
look at the gcc vectorization code handling the general vector reduction meta operation, then see if this pattern is a macro of some sort within it.

Take a step back and look at the gcc RISCV autovectorization code.  It's changing quite frequently, so it's probably premature to try and abstract out
loop reduction models that we can get Ghidra to recognize.  When that happens we might draw source exemplars from
`gcc/gcc/testsuite/gcc.target/riscv/rvv/autovec` and build a catalog of source pattern to instruction pattern expansions.

### Example: source code use of RISCV vector intrinsics

The previous example showed an overly aggressive autovectorization of a simple loop.  Here we look at source code that the developer has decided is important enough
to directly code in RISCV intrinsic C functions.  The function `ggml_vec_dot_q5_0_q8_0` is one such function, with separate implementations for `ARM_NEON`, `wasm_simd128`,
`AVX2`, `AVX`, and `riscv_v_intrinsic`.  If none of those accelerators are available a scalar implementation is used instead:

```c
void ggml_vec_dot_q5_0_q8_0(const int n, float * restrict s, const void * restrict vx, const void * restrict vy) {
    const int qk = QK8_0;
    const int nb = n / qk;

    assert(n % qk == 0);
    assert(qk == QK5_0);

    const block_q5_0 * restrict x = vx;
    const block_q8_0 * restrict y = vy;

    // scalar
    float sumf = 0.0;

    for (int i = 0; i < nb; i++) {
        uint32_t qh;
        memcpy(&qh, x[i].qh, sizeof(qh));

        int sumi = 0;

        for (int j = 0; j < qk/2; ++j) {
            const uint8_t xh_0 = ((qh & (1u << (j + 0 ))) >> (j + 0 )) << 4;
            const uint8_t xh_1 = ((qh & (1u << (j + 16))) >> (j + 12));

            const int32_t x0 = ((x[i].qs[j] & 0x0F) | xh_0) - 16;
            const int32_t x1 = ((x[i].qs[j] >>   4) | xh_1) - 16;

            sumi += (x0 * y[i].qs[j]) + (x1 * y[i].qs[j + qk/2]);
        }

        sumf += (GGML_FP16_TO_FP32(x[i].d)*GGML_FP16_TO_FP32(y[i].d)) * sumi;
    }

    *s = sumf;
}
```

The RISCV intrinsic source is:

>Note: added comments are flagged with `///`

```c
void ggml_vec_dot_q5_0_q8_0(const int n, float * restrict s, const void * restrict vx, const void * restrict vy) {
    const int qk = QK8_0;  /// QK8_0 = 32
    const int nb = n / qk;

    assert(n % qk == 0);
    assert(qk == QK5_0);   /// QK5_0 = 32

    const block_q5_0 * restrict x = vx;
    const block_q8_0 * restrict y = vy;

    float sumf = 0.0;

    uint32_t qh;

    size_t vl = __riscv_vsetvl_e8m1(qk/2);

    // These temporary registers are for masking and shift operations
    vuint32m2_t vt_1 = __riscv_vid_v_u32m2(vl);
    vuint32m2_t vt_2 = __riscv_vsll_vv_u32m2(__riscv_vmv_v_x_u32m2(1, vl), vt_1, vl);

    vuint32m2_t vt_3 = __riscv_vsll_vx_u32m2(vt_2, 16, vl);
    vuint32m2_t vt_4 = __riscv_vadd_vx_u32m2(vt_1, 12, vl);

    for (int i = 0; i < nb; i++) {
        memcpy(&qh, x[i].qh, sizeof(uint32_t));

        // ((qh & (1u << (j + 0 ))) >> (j + 0 )) << 4;
        vuint32m2_t xha_0 = __riscv_vand_vx_u32m2(vt_2, qh, vl);
        vuint32m2_t xhr_0 = __riscv_vsrl_vv_u32m2(xha_0, vt_1, vl);
        vuint32m2_t xhl_0 = __riscv_vsll_vx_u32m2(xhr_0, 4, vl);

        // ((qh & (1u << (j + 16))) >> (j + 12));
        vuint32m2_t xha_1 = __riscv_vand_vx_u32m2(vt_3, qh, vl);
        vuint32m2_t xhl_1 = __riscv_vsrl_vv_u32m2(xha_1, vt_4, vl);

        // narrowing
        vuint16m1_t xhc_0 = __riscv_vncvt_x_x_w_u16m1(xhl_0, vl);
        vuint8mf2_t xh_0 = __riscv_vncvt_x_x_w_u8mf2(xhc_0, vl);

        vuint16m1_t xhc_1 = __riscv_vncvt_x_x_w_u16m1(xhl_1, vl);
        vuint8mf2_t xh_1 = __riscv_vncvt_x_x_w_u8mf2(xhc_1, vl);

        // load
        vuint8mf2_t tx = __riscv_vle8_v_u8mf2(x[i].qs, vl);

        vint8mf2_t y0 = __riscv_vle8_v_i8mf2(y[i].qs, vl);
        vint8mf2_t y1 = __riscv_vle8_v_i8mf2(y[i].qs+16, vl);

        vuint8mf2_t x_at = __riscv_vand_vx_u8mf2(tx, 0x0F, vl);
        vuint8mf2_t x_lt = __riscv_vsrl_vx_u8mf2(tx, 0x04, vl);

        vuint8mf2_t x_a = __riscv_vor_vv_u8mf2(x_at, xh_0, vl);
        vuint8mf2_t x_l = __riscv_vor_vv_u8mf2(x_lt, xh_1, vl);

        vint8mf2_t x_ai = __riscv_vreinterpret_v_u8mf2_i8mf2(x_a);
        vint8mf2_t x_li = __riscv_vreinterpret_v_u8mf2_i8mf2(x_l);

        vint8mf2_t v0 = __riscv_vsub_vx_i8mf2(x_ai, 16, vl);
        vint8mf2_t v1 = __riscv_vsub_vx_i8mf2(x_li, 16, vl);

        vint16m1_t vec_mul1 = __riscv_vwmul_vv_i16m1(v0, y0, vl);
        vint16m1_t vec_mul2 = __riscv_vwmul_vv_i16m1(v1, y1, vl);

        vint32m1_t vec_zero = __riscv_vmv_v_x_i32m1(0, vl);

        vint32m1_t vs1 = __riscv_vwredsum_vs_i16m1_i32m1(vec_mul1, vec_zero, vl);
        vint32m1_t vs2 = __riscv_vwredsum_vs_i16m1_i32m1(vec_mul2, vs1, vl);

        int sumi = __riscv_vmv_x_s_i32m1_i32(vs2);

        sumf += (GGML_FP16_TO_FP32(x[i].d)*GGML_FP16_TO_FP32(y[i].d)) * sumi;
    }

    *s = sumf;
}
```

Ghidra's 11.1 isa_ext rendering of this is (after minor parameter name propagation):

```c
long ggml_vec_dot_q5_0_q8_0(ulong n,float *s,void *vx,void *vy)

{
  ushort *puVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  undefined8 uVar6;
  int i;
  float fVar7;
  undefined auVar8 [256];
  undefined auVar9 [256];
  undefined auVar10 [256];
  undefined auVar11 [256];
  undefined in_v7 [256];
  undefined in_v8 [256];
  undefined auVar12 [256];
  undefined auVar13 [256];
  undefined auVar14 [256];
  undefined auVar15 [256];
  undefined auVar16 [256];
  int iStack_4;
  
  gp = &__global_pointer$;
  uVar6 = vsetivli(0x10,0xc0);
  vsetvli(uVar6,0xd1);
  auVar13 = vid_v();
  vmv_v_i(in_v8,1);
  auVar15 = vadd_vi(auVar13,0xc);
  auVar12 = vsll_vv(in_v8,auVar13);
  auVar14 = vsll_vi(auVar12,0x10);
  if (0x1f < (long)n) {
    fVar7 = 0.0;
    vsetvli_e32m1tama(uVar6);
    lVar3 = (long)vx + 2;
    lVar4 = (long)vy + 2;
    i = 0;
    vmv_v_i(in_v7,0);
    vsetivli(4,0xc6);
    do {
      auVar8 = vle8_v(lVar3);
      vse8_v(auVar8,&iStack_4);
      puVar1 = (ushort *)(lVar4 + -2);
      vsetvli(uVar6,0xd1);
      lVar2 = lVar3 + 4;
      auVar8 = vle8_v(lVar2);
      auVar9 = vand_vx(auVar12,(long)iStack_4);
      auVar9 = vsrl_vv(auVar9,auVar13);
      vsetvli(0,199);
      auVar11 = vand_vi(auVar8,0xf);
      vsetvli(0,0xd1);
      auVar9 = vsll_vi(auVar9,4);
      vsetvli(0,199);
      auVar8 = vsrl_vi(auVar8,4);
      vsetvli(0,200);
      auVar9 = vncvt_xxw(auVar9);
      auVar16 = vle8_v(lVar4);
      vsetvli(0,199);
      auVar9 = vncvt_xxw(auVar9);
      vsetvli(0,0xd1);
      auVar10 = vand_vx(auVar14,(long)iStack_4);
      vsetvli(0,199);
      auVar11 = vor_vv(auVar11,auVar9);
      vsetvli(0,0xd1);
      auVar9 = vsrl_vv(auVar10,auVar15);
      vsetvli(0,199);
      auVar10 = vadd_vi(auVar11,0xfffffffffffffff0);
      vsetvli(0,200);
      auVar9 = vncvt_xxw(auVar9);
      vsetvli(0,199);
      auVar10 = vwmul_vv(auVar10,auVar16);
      auVar9 = vncvt_xxw(auVar9);
      vsetvli(0,200);
      lVar5 = lVar4 + 0x10;
      auVar10 = vwredsum_vs(auVar10,in_v7);
      vsetvli(0,199);
      auVar8 = vor_vv(auVar8,auVar9);
      auVar9 = vle8_v(lVar5);
      auVar8 = vadd_vi(auVar8,0xfffffffffffffff0);
      auVar8 = vwmul_vv(auVar8,auVar9);
      vsetvli(0,200);
      auVar8 = vwredsum_vs(auVar8,auVar10);
      vsetivli(4,0xd0);
      vmv_x_s(auVar15,auVar8);
      i = i + 1;
      lVar4 = lVar4 + 0x22;
      fVar7 = (float)(&ggml_table_f32_f16)[*puVar1] *
              (float)(&ggml_table_f32_f16)[*(ushort *)(lVar3 + -2)] * (float)(int)lVar5 + fVar7;
      lVar3 = lVar3 + 0x16;
    } while (i < (int)(((uint)((int)n >> 0x1f) >> 0x1b) + (int)n) >> 5);
    *s = fVar7;
    return lVar2;
  }
  *s = 0.0;
  return n;
}
```

It looks like the developer unrolled an inner loop and used the LMUL multiplier to help reduce the loop iterations.  The immediate action item for us may be to
add more explicit decodings for `vsetvli` and `vsetivli`, or look for existing processor-specific decoders in the Ghidra decompiler.

### x86_64 whisper

Let's take a glance at the x86_64 build of `whisper`.  First copy `whisper-cpp.BUILD` into the x86_64 workspace then build the executable with two architectures:

```console
$ bazel build --platforms=//platforms:x86_64_default --copt="-march=x86-64-v3" @whisper_cpp//:main
...
$ cp bazel-bin/external/whisper_cpp/main ../exemplars/whisper_cpp_x86-64-v3
...
$ bazel build --platforms=//platforms:x86_64_default --copt="-march=x86-64-v4" @whisper_cpp//:main
...
$ cp bazel-bin/external/whisper_cpp/main ../exemplars/whisper_cpp_x86-64-v4
```

Load these into Ghidra 11.1-DEV.  The `x86-64-v4` build is useless in Ghidra, since a different class of x86_64 vector extensions is used in that newer microarchitecture
and Ghidra doesn't recognize it.  The `x86-64-v3` build looks accessible.

Try an x86_64 build with the local compiler (Fedora 39 default compiler) and LInk Time Optimization enabled:

```console
$ bazel build  --copt="-march=x86-64-v3" --copt="-flto"  --linkopt="-Wl,-flto" @whisper_cpp//:main
...
$ cp bazel-bin/external/whisper_cpp/main ../exemplars/whisper_cpp_x86-64-v3-lto
```

We'll leave the differential analysis of link time optimization for another day.  A couple of quick notes are worthwhile here:

* The function `ggml_new_tensor` no longer exists in the binary.  Instead we get `ggml_new_tensor_impl.constprop.0`
  `ggml_new_tensor_impl.constprop.0`, `ggml_new_tensor_impl.constprop.2`, and `ggml_new_tensor_impl.constprop.3`.
  This suggests BSIM could get confused with intermediate functions if trying to connect binaries built with and without LTO.
* *None* of the hermetic toolchains appear to work when link time optimization is requested.  There appears to be at least one missing
  LTO plugin from the gcc-14 toolchain packaging.  We'll try and find such for the next snapshot of gcc-14.
