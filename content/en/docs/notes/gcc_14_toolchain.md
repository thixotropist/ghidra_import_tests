---
title: Building a gcc-14 toolchain
linkTitle: Building a gcc-14 toolchain
weight: 80
---

{{% pageinfo %}}
Building a new toolchain can be messy. 
{{% /pageinfo %}}

A C or C++ toolchain needs at least three components:

* kernel - to supply key header files and loader dependencies
* binutils - to supply assembler and linker
* gcc - to supply the compiler and compiler dependencies
* glibc - to supply key libraries and header files
* sysroot - a directory containing the libraries and resources expected for the root of the target system

These components have cross-dependencies.  A full gcc build needs libc.so from glibc.  A full glibc build needs libgcc from gcc.
There are different ways to handle these cross-dependencies, such as splitting the gcc build into two phases or prepopulating
the build directories with 'close-enough' files from a previous build.

The `sysroot` component is the trickiest to handle, since gcc and glibc need to pull files from the `sysroot` as they update files within `sysroot`.
You can generally start with a bootstrap `sysroot`, say from a previous toolchain, then update it with the latest binutils, gcc, and glibc.

Start with a released tarball for gcc and glibc.  We'll use the development tip of binutils for this pass.

Copy kernel header files into `/opt/riscv/sysroot/usr/include/`.

Configure and install binutils:

```console
$ /home2/vendor/binutils-gdb/configure --prefix=/opt/riscv/sysroot --with-sysroot=/opt/riscv/sysroot --target=riscv64-unknown-linux-gnu
$ make -j4
$ make install
```

Configure and install minimal gcc:

```console
$ /home2/vendor/gcc-14.1.0/configure --prefix=/opt/riscv --enable-languages=c,c++ --disable-multilib --target=riscv64-unknown-linux-gnu --with-sysroot=/opt/riscv/sysroot
$ make all-gcc
$ make install-gcc
```
Configure and install glibc

```console
$ ../../vendor/glibc-2.39/configure --host=riscv64-unknown-linux-gnu --target=riscv64-unknown-linux-gnu --prefix=/opt/riscv --disable-werror --enable-shared --disable-multilib --with-headers=/opt/riscv/sysroot/usr/include
$ make install-bootstrap-headers=yes install_root=/opt/riscv/sysroot install-headers
```

## Cleaning sysroot of bootstrap artifacts

How do we replace any older sysroot bootstrap files with their freshly built versions?  The most common problems involve libgcc*, libc*, and crt* files.
The bootstrap sysroot needs these files to exist.  The toolchain build process should replace them, but it may not replace all instances of these files.

Let's scrub the libgcc files, comparing the gcc directory in which they are built with the sysroot directories in which they will be saved.

```console
$ B=/home2/build_riscv/gcc
$ S=/opt/riscv/sysroot
$ find $B $S -name libgcc_s.so -ls
 57940911      4 -rw-r--r--   1 ____     ____          132 May 10 12:28 /home2/build_riscv/gcc/gcc/libgcc_s.so
 57940908      4 -rw-r--r--   1 ____     ____          132 May 10 12:28 /home2/build_riscv/gcc/riscv64-unknown-linux-gnu/libgcc/libgcc_s.so
 14361792      4 -rw-r--r--   1 ____     ____          132 May 10 12:32 /opt/riscv/sysroot/riscv64-unknown-linux-gnu/lib/libgcc_s.so
 14351655      4 -rw-r--r--   1 ____     ____          132 May 10 08:52 /opt/riscv/sysroot/lib/libgcc_s.so
 $ diff /opt/riscv/sysroot/lib/libgcc_s.so /opt/riscv/sysroot/riscv64-unknown-linux-gnu/lib/libgcc_s.so
 $ $ cat /opt/riscv/sysroot/lib/libgcc_s.so
/* GNU ld script
   Use the shared library, but some functions are only in
   the static library.  */
GROUP ( libgcc_s.so.1 -lgcc )
$ 
 ```
* `/opt/riscv/sysroot/lib/libgcc_s.so` is our bootstrap input
* `/home2/build_riscv/gcc/gcc/libgcc_s.so` and `/home2/build_riscv/gcc/riscv64-unknown-linux-gnu/libgcc/libgcc_s.so` are the generated outputs
* the bootstrap input is identical to the generate output
* neither input nor output contain absolute paths

Now check `libgcc_s.so.1` for staleness:

```console
$ find $B $S -name libgcc_s.so.1 -ls
 57940910    700 -rw-r--r--   1 ____     ____       713128 May 10 12:28 /home2/build_riscv/gcc/gcc/libgcc_s.so.1
 57946454    700 -rwxr-xr-x   1 ____     ____       713128 May 10 12:28 /home2/build_riscv/gcc/riscv64-unknown-linux-gnu/libgcc/libgcc_s.so.1
 14361791    700 -rw-r--r--   1 ____     ____       713128 May 10 12:32 /opt/riscv/sysroot/riscv64-unknown-linux-gnu/lib/libgcc_s.so.1
 14351656    696 -rw-r--r--   1 ____     ____       708624 May 10 08:53 /opt/riscv/sysroot/lib/libgcc_s.so.1
 ```

That looks like a potential problem.  The older bootstrap file is older and smaller than the generated files.  We need to fix that:

```console
$ rm /opt/riscv/sysroot/lib/libgcc_s.so.1
$ ln /opt/riscv/sysroot/riscv64-unknown-linux-gnu/lib/libgcc_s.so.1 /opt/riscv/sysroot/lib/libgcc_s.so.1
```

Next check the crt* files:

```console
$ find $B $S -name crt\*.o -ls
 57940817      8 -rw-r--r--   1 ____     ____         4248 May 10 12:28 /home2/build_riscv/gcc/gcc/crtbeginS.o
 57940826      4 -rw-r--r--   1 ____     ____          848 May 10 12:28 /home2/build_riscv/gcc/gcc/crtn.o
 57940824      4 -rw-r--r--   1 ____     ____          848 May 10 12:28 /home2/build_riscv/gcc/gcc/crti.o
 57940827      8 -rw-r--r--   1 ____     ____         4712 May 10 12:28 /home2/build_riscv/gcc/gcc/crtbeginT.o
 57940822      4 -rw-r--r--   1 ____     ____         1384 May 10 12:28 /home2/build_riscv/gcc/gcc/crtendS.o
 57940823      4 -rw-r--r--   1 ____     ____         1384 May 10 12:28 /home2/build_riscv/gcc/gcc/crtend.o
 57940815      4 -rw-r--r--   1 ____     ____         3640 May 10 12:28 /home2/build_riscv/gcc/gcc/crtbegin.o
 57940800      8 -rw-r--r--   1 ____     ____         4248 May  9 16:00 /home2/build_riscv/gcc/riscv64-unknown-linux-gnu/libgcc/crtbeginS.o
 57940808      4 -rw-r--r--   1 ____     ____          848 May  9 16:00 /home2/build_riscv/gcc/riscv64-unknown-linux-gnu/libgcc/crtn.o
 57940806      4 -rw-r--r--   1 ____     ____          848 May  9 16:00 /home2/build_riscv/gcc/riscv64-unknown-linux-gnu/libgcc/crti.o
 57940803      8 -rw-r--r--   1 ____     ____         4712 May  9 16:00 /home2/build_riscv/gcc/riscv64-unknown-linux-gnu/libgcc/crtbeginT.o
 57940812      4 -rw-r--r--   1 ____     ____         1384 May  9 16:00 /home2/build_riscv/gcc/riscv64-unknown-linux-gnu/libgcc/crtendS.o
 57940804      4 -rw-r--r--   1 ____     ____         1384 May  9 16:00 /home2/build_riscv/gcc/riscv64-unknown-linux-gnu/libgcc/crtend.o
 57940798      4 -rw-r--r--   1 ____     ____         3640 May  9 16:00 /home2/build_riscv/gcc/riscv64-unknown-linux-gnu/libgcc/crtbegin.o
 14351609     16 -rw-r--r--   1 ____     ____        13848 May 10 08:48 /opt/riscv/sysroot/usr/lib/crt1.o
 14351614      4 -rw-r--r--   1 ____     ____          952 May 10 08:48 /opt/riscv/sysroot/usr/lib/crti.o
 14351623      4 -rw-r--r--   1 ____     ____          952 May 10 08:49 /opt/riscv/sysroot/usr/lib/crtn.o
 14361798      8 -rw-r--r--   1 ____     ____         4248 May 10 12:32 /opt/riscv/sysroot/lib/gcc/riscv64-unknown-linux-gnu/14.1.0/crtbeginS.o
 14361802      4 -rw-r--r--   1 ____     ____         3640 May 10 12:32 /opt/riscv/sysroot/lib/gcc/riscv64-unknown-linux-gnu/14.1.0/crtbegin.o
 14361803      4 -rw-r--r--   1 ____     ____         1384 May 10 12:32 /opt/riscv/sysroot/lib/gcc/riscv64-unknown-linux-gnu/14.1.0/crtend.o
 14361804      4 -rw-r--r--   1 ____     ____          848 May 10 12:32 /opt/riscv/sysroot/lib/gcc/riscv64-unknown-linux-gnu/14.1.0/crti.o
 14361805      4 -rw-r--r--   1 ____     ____          848 May 10 12:32 /opt/riscv/sysroot/lib/gcc/riscv64-unknown-linux-gnu/14.1.0/crtn.o
 14361806      4 -rw-r--r--   1 ____     ____         1384 May 10 12:32 /opt/riscv/sysroot/lib/gcc/riscv64-unknown-linux-gnu/14.1.0/crtendS.o
 14361807      8 -rw-r--r--   1 ____     ____         4712 May 10 12:32 /opt/riscv/sysroot/lib/gcc/riscv64-unknown-linux-gnu/14.1.0/crtbeginT.o
 ```

 The files in `/opt/riscv/sysroot/usr/lib` are likely the bootstrap files.  The sysroot files are identical to the build files, with exceptions:

 * `crt1.o` is not generated by the gcc compiler build process.  It *may* be something provided by the kernel build.
 * `crti.o` and `crtn.o` bootstrap files and generated files are different.  If we wanted to use this updated sysroot to build a 14.2.0 toolchain,
   we probably want to use the newer versions.

So replace the bootstrap `/opt/riscv/sysroot/usr/lib/crt*.o` with hard links to the generated files.
