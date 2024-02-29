---
title: A vectorization case study
linkTitle: Vectorization case study
weight: 20
---

{{% pageinfo %}}
Compare and debug human and gcc vectorization
{{% /pageinfo %}}

This case study compares human and compiler vectorization of a simple ML quantization algorithm.  We'll assume we need to inspect the code to understand why these two
binaries sometimes produce different results.  Our primary goal is to see whether we can improve Ghidra's riscv pcode generation to make such analyses easier.  A  secondary
goal is to collect generated instruction patterns that may help Ghidra users understand what optimizing vectorizing compilers can do to source code.

The ML algorithm under test comes from https://github.com/ggerganov/llama.cpp.  It packs an array of 32 bit floats into a set of q8_0 blocks to condense large
model files.  The q8_0 quantization reduces 32 32 bit floating point numbers to 32 8 bit integers with an associated 16 bit floating point scale factor.

The `ggml-quants.c` file in the `llama.cpp` repo provides both scalar source code (`quantize_row_q8_0_reference`) and hand-generated vectorized source code (`quantize_row_q8_0`).

* The `quantize_row_q8_0` function has several `#ifdef` sections providing hand-generated vector intrinsics for riscv, avx2, arm/neon, and wasm.
* The `quantize_row_q8_0_reference` function source uses more loops but no vector instructions.  GCC-14 will autovectorize the scalar `quantize_row_q8_0_reference`,
  producing vector code that is quite different from the hand-generated vector intrinsics.

The notional AI development shop wants to use Ghidra to inspect generated assembly instructions for both `quantize_row_q8_0` and `quantize_row_q8_0_reference` to track down
reported quirks.  On some systems they produce identical results, on others the results differ.  The test framework includes:

* A target RISCV-64 processor supporting vector and compressed instructions.
* GCC-14 developmental (pending release) compiler toolchain for native x86_64 builds
* GCC-14 developmental (pending release) RISCV-64 cross-compiler toolchain with standard options `-march=rv64gcv`, `-O3`, and `-ffast-math`.
* `qemu-riscv64-static` emulated execution of user space riscv-64 applications on an x86_64 linux test server.
* A generic unit testing framework like `gtest`.
* Ghidra 11+ with the `isa_ext` branch supporting  riscv 1.0 vector instructions.

The unit test process involves three unit test executions:

* a reference x86_64 execution to test the logic on a common platform.
* within a `qemu-riscv64-static` environment with an emulated VLEN=256 bits
* within a `qemu-riscv64-static` environment with an emulated VLEN=128 bits

>Note: This exercise uses whisper C and C++ source code as 'ground truth', coupled with a C++ test framework.
>      If we didn't have source code, we would have to reconstruct key library source files based
>      on Ghidra inspection, then refine those reconstructions until Ghidra and unit testing shows that our
>      reconstructions behave the same as the original binaries.

As setup to the Ghidra inspection, we will build and run all three and expect
to see three PASSED notifications:

```console
$ bazel run -platforms=//platforms:x86_64 case_studies:unitTests
...

INFO: Analyzed target //case_studies:unitTests (0 packages loaded, 0 targets configured).
INFO: Found 1 target...
Target //case_studies:unitTests up-to-date:
  bazel-bin/case_studies/unitTests
INFO: Elapsed time: 21.065s, Critical Path: 20.71s
INFO: 37 processes: 2 internal, 35 linux-sandbox.
INFO: Build completed successfully, 37 total actions
INFO: Running command line: bazel-bin/case_studies/unitTests
[==========] Running 2 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 2 tests from FP16
[ RUN      ] FP16.convertFromFp32Reference
[       OK ] FP16.convertFromFp32Reference (0 ms)
[ RUN      ] FP16.convertFromFp32VectorIntrinsics
[       OK ] FP16.convertFromFp32VectorIntrinsics (0 ms)
[----------] 2 tests from FP16 (0 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test suite ran. (0 ms total)
[  PASSED  ] 2 tests.

$ bazel build --platforms=//platforms:riscv_vector case_studies:unitTests
$ bazel build --platforms=//platforms:riscv_vector --define __riscv_v_intrinsics=1 case_studies:unitTests
WARNING: Build option --platforms has changed, discarding analysis cache (this can be expensive, see https://bazel.build/advanced/performance/iteration-speed).
INFO: Analyzed target //case_studies:unitTests (0 packages loaded, 1904 targets configured).
...
INFO: Found 1 target...
Target //case_studies:unitTests up-to-date:
  bazel-bin/case_studies/unitTests
INFO: Elapsed time: 22.265s, Critical Path: 22.07s
INFO: 37 processes: 2 internal, 35 linux-sandbox.
INFO: Build completed successfully, 37 total actions
$ export QEMU_CPU=rv64,zba=true,zbb=true,v=true,vlen=256,vext_spec=v1.0,rvv_ta_all_1s=true,rvv_ma_all_1s=true
$ qemu-riscv64-static -L /opt/riscvx -E LD_LIBRARY_PATH=/opt/riscvx/riscv64-unknown-linux-gnu/lib/ bazel-bin/case_studies/unitTests
[==========] Running 2 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 2 tests from FP16
[ RUN      ] FP16.convertFromFp32Reference
[       OK ] FP16.convertFromFp32Reference (1 ms)
[ RUN      ] FP16.convertFromFp32VectorIntrinsics
[       OK ] FP16.convertFromFp32VectorIntrinsics (0 ms)
[----------] 2 tests from FP16 (2 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test suite ran. (6 ms total)
[  PASSED  ] 2 tests.

Target //case_studies:unitTests up-to-date:
  bazel-bin/case_studies/unitTests
INFO: Elapsed time: 8.984s, Critical Path: 8.88s
INFO: 29 processes: 2 internal, 27 linux-sandbox.
INFO: Build completed successfully, 29 total actions

$ QEMU_CPU=rv64,zba=true,zbb=true,v=true,vlen=256,vext_spec=v1.0,rvv_ta_all_1s=true,rvv_ma_all_1s=true
$ qemu-riscv64-static -L /opt/riscvx -E LD_LIBRARY_PATH=/opt/riscvx/riscv64-unknown-linux-gnu/lib/ bazel-bin/case_studies/unitTests
[==========] Running 2 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 2 tests from FP16
[ RUN      ] FP16.convertFromFp32Reference
[       OK ] FP16.convertFromFp32Reference (1 ms)
[ RUN      ] FP16.convertFromFp32VectorIntrinsics
[       OK ] FP16.convertFromFp32VectorIntrinsics (0 ms)
[----------] 2 tests from FP16 (2 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test suite ran. (6 ms total)
[  PASSED  ] 2 tests.

$ export QEMU_CPU=rv64,zba=true,zbb=true,v=true,vlen=128,vext_spec=v1.0,rvv_ta_all_1s=true,rvv_ma_all_1s=true
$ qemu-riscv64-static -L /opt/riscvx -E LD_LIBRARY_PATH=/opt/riscvx/riscv64-unknown-linux-gnu/lib/ bazel-bin/case_studies/unitTests
[==========] Running 2 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 2 tests from FP16
[ RUN      ] FP16.convertFromFp32Reference
[       OK ] FP16.convertFromFp32Reference (1 ms)
[ RUN      ] FP16.convertFromFp32VectorIntrinsics
case_studies/unitTests.cpp:55: Failure
Expected equality of these values:
  dest[0].d
    Which is: 12175
  fp16_test_array.d
    Which is: 13264
fp16 scale factor is correct
case_studies/unitTests.cpp:57: Failure
Expected equality of these values:
  comparison
    Which is: -65
  0
entire fp16 block is converted correctly
[  FAILED  ] FP16.convertFromFp32VectorIntrinsics (8 ms)
[----------] 2 tests from FP16 (10 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 1 test suite ran. (14 ms total)
[  PASSED  ] 1 test.
[  FAILED  ] 1 test, listed below:
[  FAILED  ] FP16.convertFromFp32VectorIntrinsics

 1 FAILED TEST
```

These results imply:

* The hand-vectorized `quantize_row_q8_0` test passes on harts with VLEN=256 but fails when
  executed on harts with VLEN=128.  Further tracing suggests that `quantize_row_q8_0` only processes the
  first 16 floats, not the 32 floats that should be processed in each block.
* The gcc autovectorized `quantize_row_q8_0_reference` passes on both types of harts.

Now we need to import the riscv-64 `unitTests` program into Ghidra and examine the compiled differences between
`quantize_row_q8_0` and `quantize_row_q8_0_reference`.

>Note: Remember that our real integration test goal is to look for new problems or regressions in Ghidra's
>      decompiler presentation of functions like these, and then to look for ways to improve that presentation.

## Original Source Code

The goal of both `quantize_row_q8_0*` routines is a lossy compression of 32 bit floats into blocks of 8 bit scaled values.
The routines should return identical results, with `quantize_row_q8_0` invoked on architectures with vector acceleration
and `quantize_row_q8_0_reference` for all other architectures.

```c
static const int QK8_0 = 32;
// reference implementation for deterministic creation of model files
void quantize_row_q8_0_reference(const float * restrict x, block_q8_0 * restrict y, int k) {
    assert(k % QK8_0 == 0);
    const int nb = k / QK8_0;

    for (int i = 0; i < nb; i++) {
        float amax = 0.0f; // absolute max

        for (int j = 0; j < QK8_0; j++) {
            const float v = x[i*QK8_0 + j];
            amax = MAX(amax, fabsf(v));
        }

        const float d = amax / ((1 << 7) - 1);
        const float id = d ? 1.0f/d : 0.0f;

        y[i].d = GGML_FP32_TO_FP16(d);

        for (int j = 0; j < QK8_0; ++j) {
            const float x0 = x[i*QK8_0 + j]*id;

            y[i].qs[j] = roundf(x0);
        }
    }
}
void quantize_row_q8_0(const float * restrict x, void * restrict vy, int k) {
    assert(QK8_0 == 32);
    assert(k % QK8_0 == 0);
    const int nb = k / QK8_0;

    block_q8_0 * restrict y = vy;

#if defined(__ARM_NEON)
...
#elif defined(__wasm_simd128__)
...
#elif defined(__AVX2__) || defined(__AVX__)
...
#elif defined(__riscv_v_intrinsic)

    size_t vl = __riscv_vsetvl_e32m4(QK8_0);

    for (int i = 0; i < nb; i++) {
        // load elements
        vfloat32m4_t v_x   = __riscv_vle32_v_f32m4(x+i*QK8_0, vl);

        vfloat32m4_t vfabs = __riscv_vfabs_v_f32m4(v_x, vl);
        vfloat32m1_t tmp   = __riscv_vfmv_v_f_f32m1(0.0f, vl);
        vfloat32m1_t vmax  = __riscv_vfredmax_vs_f32m4_f32m1(vfabs, tmp, vl);
        float amax = __riscv_vfmv_f_s_f32m1_f32(vmax);

        const float d = amax / ((1 << 7) - 1);
        const float id = d ? 1.0f/d : 0.0f;

        y[i].d = GGML_FP32_TO_FP16(d);
        vfloat32m4_t x0 = __riscv_vfmul_vf_f32m4(v_x, id, vl);

        // convert to integer
        vint16m2_t   vi = __riscv_vfncvt_x_f_w_i16m2(x0, vl);
        vint8m1_t    vs = __riscv_vncvt_x_x_w_i8m1(vi, vl);

        // store result
        __riscv_vse8_v_i8m1(y[i].qs , vs, vl);
    }
#else
    GGML_UNUSED(nb);
    // scalar
    quantize_row_q8_0_reference(x, y, k);
#endif
}
```

The reference version has an outer loop iterating over scalar 32 bit floats, with two inner loops operating on blocks of 32
of those floats.  The first inner loop accumulates the maximum of absolute values within the block to generate a scale factor,
while the second inner loop applies that scale factor to each 32 bit float in the block and then converts the scaled value to an 8 bit integer.
Each output block is then a 16 bit floating point scale factor plus 32 8 bit scaled integers.

The code includes some distractions that complicate Ghidra analysis:

* The k input parameter is signed, making the integer division by 32 more complicated than it needs to be.
* The `GGML_FP32_TO_FP16(d)` conversion might be a single instruction on some architectures, but it requires branch evaluation
  on our RISCV-64 target architecture.  GCC may elect to duplicate code in order to minimize the number of branches needed.

The hand-optimized `quantize_row_q8_0` has similar distractions, plus a few more:

* The two inner loops have been converted into riscv vector intrinsics, such that each iteration processes 32 4 byte floats into
  a single 34 byte `block_q8_0` struct.
* Four adjacent vector registers are grouped with the `m4` setting.  On architectures with a vector length VLEN=256, that means
  all 32 4 byte floats per block will fit nicely and can be processed in parallel.  If the architecture only supports a vector length of
  VLEN=128, then only half of each block will be processed in every iteration.  That accounts for the unit test failure.
* The code uses standard riscv_intrinsics - of which there are nearly 40,000 variants.  The root of each intrinsic is generally a
  single vector instruction, then extended with information on the expected vector context (from vset* instructions) and the expected
  return type of the result.  There is no C header file providing signatures for all possible variants, so nothing Ghidra can import
  and use in the decompiler view.
* The `__riscv_vle32_v_f32m4` intrinsic is likely the slowest of the set, as this 32 bit instruction will require a 128 byte memory read,
  stalling the instruction pipeline for some number of cycles.

## Ghidra inspection

### inspecting the hand-vectorized quantizer

Load `unitTest` into Ghidra and inspect `quantize_row_q8_0`.  We know the correct signature so we can override what Ghidra has inferred,
then name the parameters so that they look more like the source code.

```c
void quantize_row_q8_0(float *x,block_q0_0 *y,long k)

{
  float fVar1;
  int iVar2;
  char *pcVar3;
  undefined8 uVar4;
  uint uVar5;
  int iVar6;
  ulong uVar7;
  undefined8 uVar8;
  undefined in_v1 [256];
  undefined auVar9 [256];
  undefined auVar10 [256];
  gp = &__global_pointer$;
  if (k < 0x20) {
    return;
  }
  uVar4 = vsetvli_e8m1tama(0x20);
  vsetvli_e32m1tama(uVar4);
  uVar5 = 0x106c50;
  iVar2 = (int)(((uint)((int)k >> 0x1f) >> 0x1b) + (int)k) >> 5;
  iVar6 = 0;
  vmv_v_i(in_v1,0);
  pcVar3 = y->qs;
  do {
    while( true ) {
      vsetvli_e32m4tama(uVar4);
      auVar9 = vle32_v(x);
      auVar10 = vfsgnjx_vv(auVar9,auVar9);
      auVar10 = vfredmax_vs(auVar10,in_v1);
      uVar8 = vfmv_fs(auVar10);
      fVar1 = (float)uVar8 * 0.007874016;
      uVar7 = (ulong)(uint)fVar1;
      if ((fVar1 == 0.0) || (uVar7 = (ulong)(uint)(127.0 / (float)uVar8), uVar5 << 1 < 0xff000001))
      break;
      auVar9 = vfmul_vf(auVar9,uVar7);
      vsetvli_e16m2tama(0);
      ((block_q0_0 *)(pcVar3 + -2))->d = 0x7e00;
      auVar9 = vfncvt_xfw(auVar9);
      iVar6 = iVar6 + 1;
      vsetvli_e8m1tama(0);
      auVar9 = vncvt_xxw(auVar9);
      vse8_v(auVar9,pcVar3);
      x = x + 0x20;
      pcVar3 = pcVar3 + 0x22;
      if (iVar2 <= iVar6) {
        return;
      }
    }
    iVar6 = iVar6 + 1;
    auVar9 = vfmul_vf(auVar9,uVar7);
    vsetvli_e16m2tama(0);
    auVar9 = vfncvt_xfw(auVar9);
    vsetvli_e8m1tama(0);
    auVar9 = vncvt_xxw(auVar9);
    vse8_v(auVar9,pcVar3);
    x = x + 0x20;
    uVar5 = uVar5 & 0xfff;
    ((block_q0_0 *)(pcVar3 + -2))->d = (short)uVar5;
    pcVar3 = pcVar3 + 0x22;
  } while (iVar6 < iVar2);
  return;
}
```

>Note: an earlier run showed several pcode errors in `riscv-rvv.sinc`, which have been fixed as of this run.

Red herrings - none of these have anything to do with riscv or vector intrinsics

* `uVar5 = 0x106c50;` - there is no uVar5 variable, just a shared upper immediate load register.
* `iVar2 = (int)(((uint)((int)k >> 0x1f) >> 0x1b) + (int)k) >> 5;` - since k is a signed long and not unsigned, the compiler
  has to implement the divide by 32 with rounding adjustments for negative numbers.\
* `fVar1 = (float)uVar8 * 0.007874016;` - the compiler changed a division by 127.0 into a multiplication by 0.007874016.
* `((block_q0_0 *)(pcVar3 + -2))->d` - the compiler has set pcVar3 to point to an element within the block, so it uses negative
  offsets to address preceding elements.
* duplicate code blocks - the conversion from a 32 bit float to the 16 bit float involves some branches.  The compiler has decided
  that duplicating following code for at least one branch will be faster.
* Decompiler handling of `fmv.x.w` instructions looks odd. fmv.x.w moves the single-precision value in ﬂoating-point register rs1
  represented in IEEE 754-2008 encoding to the lower 32 bits of integer register rd.  This works fine when the source
  is zero, but it has no clear C-like representation otherwise.  These may better be replaced with specialized pcode operations.

There is one discrepancy that does involve the vectorization code.  The source code uses a standard riscv vector intrinsic function
to store data:

```c
__riscv_vse8_v_i8m1(y[i].qs, vs, vl);
```

Ghidra pcode for this instruction after renaming operands is (currently):

```c
vse8_v(vs, y[i].qs);
```

The order of the first two parameters is swapped.  We should probably align the pcode to avoid deviations from the
standard intrinsic signature as much as possible.  Those intrinsics have context and type information encoded into their
name, which Ghidra does not currently have, so we can't exactly match.

### inspecting the auto-vectorized quantizer

Load `unitTest` into Ghidra and inspect `quantize_row_q8_0_reference`.  We know the correct signature so we can override what
Ghidra has inferred, then name the parameters so that they look more like the source code.

```c
void quantize_row_q8_0_reference(float *x,block_q0_0 *y,long k)

{
  float fVar1;
  long lVar2;
  long lVar3;
  char *pcVar4;
  ushort uVar5;
  int iVar6;
  ulong uVar7;
  undefined8 uVar8;
  undefined auVar9 [256];
  undefined auVar10 [256];
  undefined auVar11 [256];
  undefined auVar12 [256];
  undefined auVar13 [256];
  undefined auVar14 [256];
  undefined in_v7 [256];
  undefined auVar15 [256];
  undefined auVar16 [256];
  undefined auVar17 [256];
  undefined auVar18 [256];
  undefined auVar19 [256];

  gp = &__global_pointer$;
  if (k < 0x20) {
    return;
  }
  vsetivli_e32m1tama(4);
  pcVar4 = y->qs;
  lVar2 = 0;
  iVar6 = 0;
  auVar15 = vfmv_sf(0xff800000);
  vmv_v_i(in_v7,0);
  do {
    lVar3 = (long)x + lVar2;
    auVar14 = vle32_v(lVar3);
    auVar13 = vle32_v(lVar3 + 0x10);
    auVar10 = vfsgnjx_vv(auVar14,auVar14);
    auVar9 = vfsgnjx_vv(auVar13,auVar13);
    auVar10 = vfmax_vv(auVar10,in_v7);
    auVar9 = vfmax_vv(auVar9,auVar10);
    auVar12 = vle32_v(lVar3 + 0x20);
    auVar11 = vle32_v(lVar3 + 0x30);
    auVar10 = vfsgnjx_vv(auVar12,auVar12);
    auVar10 = vfmax_vv(auVar10,auVar9);
    auVar9 = vfsgnjx_vv(auVar11,auVar11);
    auVar9 = vfmax_vv(auVar9,auVar10);
    auVar10 = vle32_v(lVar3 + 0x40);
    auVar18 = vle32_v(lVar3 + 0x50);
    auVar16 = vfsgnjx_vv(auVar10,auVar10);
    auVar16 = vfmax_vv(auVar16,auVar9);
    auVar9 = vfsgnjx_vv(auVar18,auVar18);
    auVar9 = vfmax_vv(auVar9,auVar16);
    auVar17 = vle32_v(lVar3 + 0x60);
    auVar16 = vle32_v(lVar3 + 0x70);
    auVar19 = vfsgnjx_vv(auVar17,auVar17);
    auVar19 = vfmax_vv(auVar19,auVar9);
    auVar9 = vfsgnjx_vv(auVar16,auVar16);
    auVar9 = vfmax_vv(auVar9,auVar19);
    auVar9 = vfredmax_vs(auVar9,auVar15);
    uVar8 = vfmv_fs(auVar9);
    fVar1 = (float)uVar8 * 0.007874016;
    uVar7 = (ulong)(uint)fVar1;
    if (fVar1 == 0.0) {
LAB_00076992:
      uVar5 = ((ushort)lVar3 & 0xfff) + ((ushort)((uint)lVar3 >> 0xd) & 0x7c00);
    }
    else {
      uVar7 = (ulong)(uint)(127.0 / (float)uVar8);
      uVar5 = 0x7e00;
      if ((uint)lVar3 << 1 < 0xff000001) goto LAB_00076992;
    }
    auVar9 = vfmv_vf(uVar7);
    auVar14 = vfmul_vv(auVar14,auVar9);
    auVar14 = vfcvt_xfv(auVar14);
    auVar13 = vfmul_vv(auVar13,auVar9);
    auVar13 = vfcvt_xfv(auVar13);
    auVar12 = vfmul_vv(auVar12,auVar9);
    auVar12 = vfcvt_xfv(auVar12);
    auVar11 = vfmul_vv(auVar9,auVar11);
    auVar11 = vfcvt_xfv(auVar11);
    vsetvli_e16mf2tama(0);
    auVar14 = vncvt_xxw(auVar14);
    vsetvli_e8mf4tama(0);
    auVar14 = vncvt_xxw(auVar14);
    vse8_v(auVar14,pcVar4);
    vsetvli_e32m1tama(0);
    auVar14 = vfmul_vv(auVar9,auVar10);
    vsetvli_e16mf2tama(0);
    ((block_q0_0 *)(pcVar4 + -2))->d = (ushort)((ulong)lVar3 >> 0x10) & 0x8000 | uVar5;
    auVar10 = vncvt_xxw(auVar13);
    vsetvli_e8mf4tama(0);
    auVar10 = vncvt_xxw(auVar10);
    vse8_v(auVar10,pcVar4 + 4);
    vsetvli_e32m1tama(0);
    auVar13 = vfcvt_xfv(auVar14);
    vsetvli_e16mf2tama(0);
    auVar10 = vncvt_xxw(auVar12);
    vsetvli_e8mf4tama(0);
    auVar10 = vncvt_xxw(auVar10);
    vse8_v(auVar10,pcVar4 + 8);
    vsetvli_e32m1tama(0);
    auVar12 = vfmul_vv(auVar9,auVar18);
    vsetvli_e16mf2tama(0);
    auVar10 = vncvt_xxw(auVar11);
    vsetvli_e8mf4tama(0);
    auVar10 = vncvt_xxw(auVar10);
    vse8_v(auVar10,pcVar4 + 0xc);
    vsetvli_e32m1tama(0);
    auVar11 = vfcvt_xfv(auVar12);
    vsetvli_e16mf2tama(0);
    auVar10 = vncvt_xxw(auVar13);
    vsetvli_e8mf4tama(0);
    auVar10 = vncvt_xxw(auVar10);
    vse8_v(auVar10,pcVar4 + 0x10);
    vsetvli_e32m1tama(0);
    auVar10 = vfmul_vv(auVar9,auVar17);
    vsetvli_e16mf2tama(0);
    auVar11 = vncvt_xxw(auVar11);
    vsetvli_e8mf4tama(0);
    auVar11 = vncvt_xxw(auVar11);
    vse8_v(auVar11,pcVar4 + 0x14);
    vsetvli_e32m1tama(0);
    auVar10 = vfcvt_xfv(auVar10);
    vsetvli_e16mf2tama(0);
    auVar10 = vncvt_xxw(auVar10);
    vsetvli_e8mf4tama(0);
    auVar10 = vncvt_xxw(auVar10);
    vse8_v(auVar10,pcVar4 + 0x18);
    vsetvli_e32m1tama(0);
    auVar9 = vfmul_vv(auVar16,auVar9);
    auVar9 = vfcvt_xfv(auVar9);
    vsetvli_e16mf2tama(0);
    iVar6 = iVar6 + 1;
    auVar9 = vncvt_xxw(auVar9);
    vsetvli_e8mf4tama(0);
    auVar9 = vncvt_xxw(auVar9);
    vse8_v(auVar9,pcVar4 + 0x1c);
    lVar2 = lVar2 + 0x80;
    pcVar4 = pcVar4 + 0x22;
    if ((int)(((uint)((int)k >> 0x1f) >> 0x1b) + (int)k) >> 5 <= iVar6) {
      return;
    }
    vsetvli_e32m1tama(0);
  } while( true );
}
```

Some of the previous red herrings show up here too.  Things to note:

* `undefined auVar19 [256];` - something in `riscv-rvv.sinc` is claiming vector registers are 256 bits long - that's not generally
  true, so hunt down the confusion.
  * `riscv.reg.sinc` is the root of this, with `@define VLEN "256"` and `define register offset=0x4000 size=$(VLEN) [ v0  ...]`.
    What should Ghidra believe the size of vector registers to be?  More generally, should the size and element type of vector
    registers be mutable?
* the autovectorizer has correctly decided VLEN=128 architectures must be supported, and has dedicated 8 vector registers to
  hold all 32 floats required per loop iteration.  Unlike the hand-optimized solution, the 8 vector registers are handled
  by 8 interleaved sequences of vector instructions.  This roughly doubles the instruction count, but provides good distribution
  of load and store memory operations across the loop, likely minimizing execution stalls.

RISCV vector instruction execution engines - and autovectorization passes in gcc - are both so immature we have no idea of which
implementation performs better.  At best we can guess that autovectorization will be good enough to make hand optimized coding
with riscv intrinsic functions rarely needed.

## Vectorized function analysis without source code

Now try using Ghidra to inspect a function that dominates execution time in the whisper.cpp demo - `ggml_vec_dot_16`.  We'll do this
without first checking the source code.  We'll make a few reasonable assumptions:

* this is likely a vector dot product
* the vector elements are 16 bit floating point values of the type we've seen already.

A quick inspection lets us rewrite the function signature as:

```c
void ggml_vec_dot_f16(long n,float *sum,fp16 *x,fp16 *y) {...}
```

That quick inspection also shows a glaring error - the pcode semantics for `vluxei64.v` has left out a critical parameter.  It's present in the
listing view but missing in the pcode semantics view.  Fix this and move on.

After tinkering with variable names and signatures, we get:

```c
void ggml_vec_dot_q8_0_q8_0(long n,float *sum,block_q8_0 *x,block_q8_0 *y)

{
  block_q8_0 *pbVar1;
  int iVar2;
  char *px_qs;
  char *py_qs;
  undefined8 uVar3;
  undefined8 uVar4;
  float partial_sum;
  undefined auVar5 [256];
  undefined auVar6 [256];
  undefined in_v5 [256];

  gp = &__global_pointer$;
  partial_sum = 0.0;
  uVar4 = vsetvli_e8m1tama(0x20);
  if (0x1f < n) {
    px_qs = x->qs;
    py_qs = y->qs;
    iVar2 = 0;
    vsetvli_e32m1tama(uVar4);
    vmv_v_i(in_v5,0);
    do {
      pbVar1 = (block_q8_0 *)(px_qs + -2);
      vsetvli_e8m1tama(uVar4);
      auVar6 = vle8_v(px_qs);
      auVar5 = vle8_v(py_qs);
      auVar5 = vwmul_vv(auVar6,auVar5);
      vsetvli_e16m2tama(0);
      auVar5 = vwredsum_vs(auVar5,in_v5);
      vsetivli_e32m1tama(0);
      uVar3 = vmv_x_s(auVar5);
      iVar2 = iVar2 + 1;
      px_qs = px_qs + 0x22;
      partial_sum = (float)(int)uVar3 *
                    (float)(&ggml_table_f32_f16)[((block_q8_0 *)(py_qs + -2))->field0_0x0] *
                    (float)(&ggml_table_f32_f16)[pbVar1->field0_0x0] + partial_sum;
      py_qs = py_qs + 0x22;
    } while (iVar2 < (int)(((uint)((int)n >> 0x1f) >> 0x1b) + (int)n) >> 5);
  }
  *sum = partial_sum;
  return;
}
```

That's fairly clear - the two vectors are presented as arrays of `block_q8_0` structs, each with
32 entries and a scale factor `d`.  An earlier run showed another error, now fixed, with the pcode for
`vmv_x_s`.
