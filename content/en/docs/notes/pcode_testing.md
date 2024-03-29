---
title: Pcode testing
linkTitle: Pcode testing
weight: 40
---

{{% pageinfo %}}
Ghidra testing of semantic pcode.
{{% /pageinfo %}}

>Note: paths and names are likely to change here.  Use these notes just as a guide.

The Ghidra 11 `isa_ext` branch makes heavy use of user-defined pcode (aka Sleigh semantics).  Much of that pcode is arbitrarily defined, adding more confusion to an
already complex field.  Can we build a testing framework to highlight problem areas in pcode semantics?

For example, let's look at Ghidra's decompiler rendering of two RISCV-64 vector instructions `vmv.s.x` and `vmv.x.s`.  These instructions move a single element between an
integer scalar register and the first element of a vector register.  The [RISCV](https://github.com/riscv/riscv-v-spec/blob/master/v-spec.adoc)
vector definition says:

* The vmv.x.s instruction copies a single SEW-wide element from index 0 of the source vector register to a destination integer register.
* The vmv.s.x instruction copies the scalar integer register to element 0 of the destination vector register.

These instructions have a lot of symmetry, but the current isa_ext branch doesn't render them symmetrically.  Let's build a sample function
that uses both instructions followed by an assertion of what we expect to see.

```c
bool test_integer_scalar_vector_move() {
    ///@ exercise integer scalar moves into and out of a vector register
    int x = 1;
    int y = 0;
    // set vector mode to something simple
    __asm__ __volatile__ ("vsetivli zero,1,e32,m1,ta,ma\n\t");
    // execute both instructions to set y:= x
    __asm__ __volatile__ ("vmv.s.x  v1, %1\n\t" "vmv.x.s  %0, v1"\
                          : "=r" (y) \
                          : "r" (x) );
    return x==y;
}
```

This function should return the boolean value True.  It's defined in the file `failing_tests/pcodeSamples.cpp` and
compiled into the library `libsamples.so`.  The function is executed within the test harness `failing_tests/pcodeTests.cpp`.

Build (with O3 optimization) and execute the test harness with:

```console
$ bazel clean
INFO: Starting clean (this may take a while). Consider using --async if the clean takes more than several minutes.
$ bazel build -s -c opt  --platforms=//platforms:riscv_vector failing_tests:samples
$ cp -f bazel-bin/failing_tests/libsamples.so /tmp
$ bazel build -s -c opt  --platforms=//platforms:riscv_vector failing_tests:pcodeTests
$ export QEMU_CPU=rv64,zba=true,zbb=true,v=true,vlen=128,vext_spec=v1.0,rvv_ta_all_1s=true,rvv_ma_all_1s=true
$ qemu-riscv64-static -L /opt/riscvx -E LD_LIBRARY_PATH=/opt/riscvx/riscv64-unknown-linux-gnu/lib/ bazel-bin/failing_tests/pcodeTests
[==========] Running 1 test from 1 test suite.
[----------] Global test environment set-up.
[----------] 1 test from VectorMove
[ RUN      ] VectorMove.vmv_s_x
[       OK ] VectorMove.vmv_s_x (0 ms)
[----------] 1 test from VectorMove (0 ms total)

[----------] Global test environment tear-down
[==========] 1 test from 1 test suite ran. (3 ms total)
[  PASSED  ] 1 test.
```

Now import /tmp/libsamples.so into Ghidra and look for test* functions.  The decompilation is:

```c
bool test_integer_scalar_vector_move(void)
{
  undefined8 uVar1;
  undefined in_v1 [256];
  vsetivli_e32m1tama(1);
  vmv_s_x(in_v1,1);
  uVar1 = vmv_x_s(in_v1);
  return (int)uVar1 == 1;
}
```

This shows two issues:

* Ghidra believes vector v1 is 256 bits long, when in fact it is unknown at compile and link time.  That's
  probably OK for now, as it provides a hint that this is a vector register.
* The treatment of instruction output is inconsistent.  For `vmv_s_x`, the output is the first element of `in_v1`.
  For `vmv_x_s`, the output is the scalar register `uVar1`.  That *might* be OK, since we don't specify what
  happens to other elements of `in_v1`.

The general question raised by this example is how to treat pcode output - as an output parameter or as
a returned result?  The sleigh pcode documentation suggests that parameters are assumed to be input parameters,
with the only output register the one returned by the pcode operation.  A quick glance at the ARM Neon and AARCH64 SVE
vector sleigh files suggests that this is the convention, but perhaps not a requirement.

Let's try adding some more test cases before taking any action.

