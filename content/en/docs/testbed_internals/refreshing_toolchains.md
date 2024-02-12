---
title: refreshing toolchains
weight: 20
---

{{% pageinfo %}}
Refreshing (updating) an existing toolchain is mostly straightforward.
{{% /pageinfo %}}

>Warning: This sequence uses unreleased code for binutils, gcc, and glibc.
>         We use this experimental toolchain to get a glimpse of future toolchains and products,
>         not for stable code.

## Update binutils

binutils' latest release is 2.42.  Let's update our RISCV toolchain to use the current binutils head,
which is currently very close to the released version.  The git log shows relatively little change
to the RISCV assembler, other than some corrections to the THead extension encodings.

* Update the source directory to commit a197d5f7eb27e99c27577, January 18 2024.  RISCV updates to
  the previous snapshot have landed from various alibaba contributors.
* switch to the binutils build directory and refresh the configuration, build, and install to `/opt/riscvx`.

```console
$ /home2/vendor/binutils-gdb/configure --prefix=/opt/riscvx --target=riscv64-unknown-linux-gnu
$ make
$ make install
```

## Update gcc

* Update to the tip of the master branch, glancing at the log to see that alibaba, intel, rivai,
rivos, and others have contributed recent RISCV updates.
* switch to the existing build directory, clean the old configuration, and repeat the configuration
  used before.
* make and install to `/opt/riscvx`

```console
$ make distclean
$ /home2/vendor/gcc/configure --prefix=/opt/riscvx --enable-languages=c,c++,lto --disable-multilib --target=riscv64-unknown-linux-gnu --with-sysroot=/opt/riscvx/sysroot
$ make
$ make install
```

## update glibc

Update the source directory to the tip of the master branch, refresh the configuration, build,
and install

```console
$ ../../vendor/glibc/configure CC=/opt/riscvx/bin/riscv64-unknown-linux-gnu-gcc  --host=riscv64-unknown-linux-gnu --target=riscv64-unknown-linux-gnu --prefix=/opt/riscvx --disable-werror --enable-shared --disable-multilib
$ make
$ make install
```

## testing the refreshed toolchain

The previous steps generate a new, non-portable toolchain under `/opt/riscvx`.  Before we can generate the portable tarball
(e.g., `risc64_linux_gcc-14.0.1.tar.xz`) we can exercise the newer toolchain.  If we pass `--platforms=//platforms:riscv_local`
to bazel it will use a toolchain loaded from local files under `/opt/riscvx` instead of files extracted from the portable tarball.

This is mostly useful in debugging the bazel 'sandbox' - recognizing newer files required by the toolchain that have been installed
locally but not explicitly included in the portable tarball.

For example, suppose we are refreshing the gcc-14 toolchain from `14.0.0` to `14.0.1`.  The following sequence of builds should all succeed:

```console
# build with an unrelated and fully released toolchain as a control experiment
$ bazel build --platforms=//platforms:riscv_userspace @whisper_cpp//:main
...
Target @@whisper_cpp//:main up-to-date:
  bazel-bin/external/whisper_cpp/main        /// build was successful
...
$ strings bazel-bin/external/whisper_cpp/main|grep GCC
GCC_3.0
GCC: (GNU) 13.2.1 20230901                   /// the released compiler only was used
GCC: (g3f23fa7e74f) 13.2.1 20230901
_Unwind_Resume@GCC_3.0

# repeat with the local toolchain introducing 14.0.1 for the application build
$ bazel build --platforms=//platforms:riscv_local @whisper_cpp//:main
...
Target @@whisper_cpp//:main up-to-date:
  bazel-bin/external/whisper_cpp/main       /// build was successful
...
$ strings bazel-bin/external/whisper_cpp/main|grep GCC
GCC_3.0
GCC: (GNU) 13.2.1 20230901                  /// some system files were previously compiled
GCC: (GNU) 14.0.1 20240130 (experimental)   /// the new toolchain was used in part
_Unwind_Resume@GCC_3.0

# repeat with the candidate portable tarball
$ bazel build --platforms=//platforms:riscv_vector @whisper_cpp//:main
...
Target @@whisper_cpp//:main up-to-date:
  bazel-bin/external/whisper_cpp/main       /// build was successful
...
$ strings bazel-bin/external/whisper_cpp/main|grep GCC
GCC_3.0
GCC: (GNU) 13.2.1 20230901
GCC: (GNU) 14.0.1 20240130 (experimental)   /// the new toolchain was used in part
_Unwind_Resume@GCC_3.0
```

Different build options can require different files in the portable tarball, so this kind of test may
fail for some projects while succeeding in others.  That's easily fixed by updating the `generate.sh` `rsync` script
that builds the portable tarball.
