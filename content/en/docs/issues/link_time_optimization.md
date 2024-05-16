---
title: link time optimization
weight: 30
---

{{% pageinfo %}}
Link Time Optimization
{{% /pageinfo %}}

Link Time Optimization (LTO) is a relatively new form of toolchain optimization that can produce
smaller and faster binaries.  It can also mutate control flows in those binaries making
Ghidra analysis trickier, especially if one is using BSIM to look for control flow
similarities.

Can we generate importable exemplars using LTO to show what such optimization steps look like in Ghidra?

LTO needs a command line parameter added for both compilation and linking.  With bazel, that means
`--copt="-flto" --linkopt="-Wl,-flto"` is enough to request LTO optimization on a build.  These `lto` flags
can also be defaulted into the toolchain definition or individual build files.

Let's try this with a progressively more complicated series of exemplars

```console
# Build helloworld without LTO as a control
$ bazel build -s --copt="-O2" --platforms=//platforms:riscv_vector userSpaceSamples:helloworld
...
$ ls -l bazel-bin/userSpaceSamples/helloworld
-r-xr-xr-x. 1 --- --- 8624 Jan 31 10:44 bazel-bin/userSpaceSamples/helloworld

# The helloworld exemplar doesn't benefit much from link time optimization
$ bazel build -s  --copt="-O2"  --copt="-flto" --linkopt="-Wl,-flto" --platforms=//platforms:riscv_vector userSpaceSamples:helloworld
$ ls -l bazel-bin/userSpaceSamples/helloworld
-r-xr-xr-x. 1 --- --- 8608 Jan 31 10:46 bazel-bin/userSpaceSamples/helloworld
```

The `memcpy` source exemplar can be built three ways:

* without vector extensions and without LTO - build target `gcc_vectorization:memcpy`
* with vector extensions and without LTO - build target `gcc_vectorization:memcpy_vector`
* with vector extensions and with LTO - build target `gcc_vectorization:memcpy_lto`

In this case the LTO options are configured into `gcc_vectorization/BUILD`.

```console
$ bazel build -s --platforms=//platforms:riscv_vector gcc_vectorization:memcpy
...
INFO: Build completed successfully ...
$ ls -l bazel-bin/gcc_vectorization/memcpy
-r-xr-xr-x. 1 --- --- 13488 Jan 31 11:16 bazel-bin/gcc_vectorization/memcpy
$ bazel build -s  --platforms=//platforms:riscv_vector gcc_vectorization:memcpy_vector
INFO: Build completed successfully ...
$ ls -l bazel-bin/gcc_vectorization/memcpy_vector
-r-xr-xr-x. 1 --- --- 13728 Jan 31 11:18 bazel-bin/gcc_vectorization/memcpy_vector
$ bazel build -s  --platforms=//platforms:riscv_vector gcc_vectorization:memcpy_lto
ERROR: ...: Linking gcc_vectorization/memcpy_lto failed: (Exit 1): gcc failed: error executing CppLink command (from target //gcc_vectorization:memcpy_lto) ...
lto1: internal compiler error: in riscv_hard_regno_nregs, at config/riscv/riscv.cc:8058
Please submit a full bug report, with preprocessed source (by using -freport-bug).
See <https://gcc.gnu.org/bugs/> for instructions.
lto-wrapper: fatal error: external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-gcc returned 1 exit status
compilation terminated.
```

So it looks like LTO has problems with RISCV vector instructions.  We'll keep testing this as more gcc 14 snapshots become available,
but as a lower priority exercise.  LTO does not seem like a popular optimization.
