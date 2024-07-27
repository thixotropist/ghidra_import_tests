---
title: Toolchain Evolutions
linkTitle: Toolchain Evolutions
weight: 60
---

{{% pageinfo %}}
How are binutils, gcc, and glibc evolving?
{{% /pageinfo %}}

We can now build exemplars with the development tips of binutils, gcc, and glibc.  If we compare the development tips
with the GCC 14.1 release we can get a better idea of future testing needs.  We may also get an idea of how stable
existing toolchain features may be.

At the moment GCC 14.1 is recently released and GCC 15 is early in the development process.  The `main` branch of this
repo builds with GCC 14.1.
The `gcc-next` branch builds with snapshots of the current binutils, gcc, and glibc repositories.
That gives us a differential test of toolchain evolution and the global parties pushing for those evolutions.

## Top down analysis

The `whisper-cpp` voice to text application (at release 1.5.4) was built using both GCC 14.1.0 and 15.0.0.  Comparing these in Ghidra gives a general sense of not much changing just yet.

| Attribute | GCC 14.1 | GCC 15.0 |
| --------- | -------- | -------- |
| all instructions | 195653 | 193995 |
| vset instructions | 3367 | 3394 |
| vector move instructions | 1490 | 1226 |
| vector load instructions | 2461 | 2251 |
| vector store instructions | 2973 | 2564 |

So at least 5% of the instructions are vector instructions, probably the result of loop transforms.

## Bottom up analysis

### binutils gas test suites

```console
$ git log origin/binutils-2_41-release-point..master -- testsuite/gas/riscv
```

This shows 61 commits in the last year, many originating from:

* [rivos](https://www.rivosinc.com/) - compare and swap Zacas extension
* [sifive](https://www.sifive.com/) - sf.cease extension, SiFive custom vector coprocessor interface
* [alibaba](https://www.alibaba.com/) - THead vector extension updates
* [iscas](http://english.is.cas.cn/) - Zabha byte and halfword atomics
* [Tsukasa OI](https://a4lg.com/) - Smcntrpmf

### gcc test suite

```console
$ git log origin/releases/gcc-14..master -- gcc/testsuite/gcc.target/riscv
```

A quick review shows RISCV commits adding mathematics - saturating addition and subtraction, along with a second
encoding (BF) for 16 bit floating point values.

### glibc

```console
$ git log origin/release/2.39/master..master -- sysdeps/riscv
```
A few contributions from Rivos suggesting their upcoming processors have fewer alignment exceptions.

