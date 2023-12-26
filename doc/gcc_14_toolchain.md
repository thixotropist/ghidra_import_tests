# Building a gcc-14 toolchain

* The target installation directory will be `/opt/riscvx`
* We will use a native gcc-14 build under `/opt/gcc14`, so `/opt/gcc14/bin` should be on the path
* start with binutils-2.41 release 

## Build steps

Start with an empty `/opt/riscvx`, then intialize git within it to give us some checkpoints

## initialize with binutils 2-41 release

```console
/home2/vendor/binutils-gdb$ git checkout binutils-2_41
Note: switching to 'binutils-2_41'.
/home2/vendor/binutils-gdb$ cd /home2/build/binutils
/home2/build/binutils$ /home2/vendor/binutils-gdb/configure --prefix=/opt/riscvx --target=riscv64-unknown-linux-gnu
/home2/build/binutils$ make
...
/home2/build/binutils$ make install
...
make[1]: Leaving directory '/home2/build/binutils'
/home2/build/binutils$ pushd /opt/riscvx
/opt/riscvx$ ls -a
.  ..  bin  .git  include  lib  riscv64-unknown-linux-gnu  share
```
/opt/riscvx$ git add *
/opt/riscvx$ git commit -m"initialize with binutils2-41"
/opt/riscvx$ git gc
/opt/riscvx$ ls
bin  include  lib  riscv64-unknown-linux-gnu  share
/opt/riscvx$ ls bin
riscv64-unknown-linux-gnu-addr2line  riscv64-unknown-linux-gnu-gdb            riscv64-unknown-linux-gnu-nm       riscv64-unknown-linux-gnu-run
riscv64-unknown-linux-gnu-ar         riscv64-unknown-linux-gnu-gdb-add-index  riscv64-unknown-linux-gnu-objcopy  riscv64-unknown-linux-gnu-size
riscv64-unknown-linux-gnu-as         riscv64-unknown-linux-gnu-gprof          riscv64-unknown-linux-gnu-objdump  riscv64-unknown-linux-gnu-strings
riscv64-unknown-linux-gnu-c++filt    riscv64-unknown-linux-gnu-ld             riscv64-unknown-linux-gnu-ranlib   riscv64-unknown-linux-gnu-strip
riscv64-unknown-linux-gnu-elfedit    riscv64-unknown-linux-gnu-ld.bfd         riscv64-unknown-linux-gnu-readelf
```

## add a gcc-14 build

>Note: at this point we don't know if we need a pre-existing sysroot

```console
/home2/build$ mkdir gcc
/home2/build$ cd gcc

/home2/build/gcc$ /home2/vendor/gcc/configure --prefix=/opt/riscvx --enable-languages=c,c++ --disable-multilib --target=riscv64-unknown-linux-gnu
/home2/build/gcc$ make
...
fatal error: pthread.h: No such file or directory
/home2/build/gcc$ make install
...
ls /opt/riscvx/bin
riscv64-unknown-linux-gnu-addr2line  riscv64-unknown-linux-gnu-c++      riscv64-unknown-linux-gnu-elfedit  riscv64-unknown-linux-gnu-gcc-14.0.0  riscv64-unknown-linux-gnu-gcc-ranlib  riscv64-unknown-linux-gnu-gcov-tool      riscv64-unknown-linux-gnu-gprof   riscv64-unknown-linux-gnu-lto-dump  riscv64-unknown-linux-gnu-objdump  riscv64-unknown-linux-gnu-run      riscv64-unknown-linux-gnu-strip
riscv64-unknown-linux-gnu-ar         riscv64-unknown-linux-gnu-c++filt  riscv64-unknown-linux-gnu-g++      riscv64-unknown-linux-gnu-gcc-ar      riscv64-unknown-linux-gnu-gcov        riscv64-unknown-linux-gnu-gdb            riscv64-unknown-linux-gnu-ld      riscv64-unknown-linux-gnu-nm        riscv64-unknown-linux-gnu-ranlib   riscv64-unknown-linux-gnu-size
riscv64-unknown-linux-gnu-as         riscv64-unknown-linux-gnu-cpp      riscv64-unknown-linux-gnu-gcc      riscv64-unknown-linux-gnu-gcc-nm      riscv64-unknown-linux-gnu-gcov-dump   riscv64-unknown-linux-gnu-gdb-add-index  riscv64-unknown-linux-gnu-ld.bfd  riscv64-unknown-linux-gnu-objcopy   riscv64-unknown-linux-gnu-readelf  riscv64-unknown-linux-gnu-strings
```

The problem is not limited to compilations looking for `pthread.h`.  Let's try compiling helloWorld.c using
both the new gcc-14 crosscompiler and the working gcc-13 crosscompiler.  The gcc-13 toolchain under `/opt/riscv`` works
while the gcc-14 toolchain under `/opt/riscvx`` fails.

```console
.../ghidra_import_tests/riscv64/toolchain/userSpaceSamples/opt/riscvx/bin/riscv64-unknown-linux-gnu-gcc helloworld.c
helloworld.c:1:10: fatal error: stdio.h: No such file or directory
    1 | #include <stdio.h>
      |          ^~~~~~~~~
compilation terminated.
...ghidra_import_tests/riscv64/toolchain/userSpaceSamples$ /opt/riscv/bin/riscv64-unknown-linux-gnu-gcc helloworld.c
gary@mini:~/projects/github/ghidra_import_tests/riscv64/toolchain/userSpaceSamples$ file a.out
a.out: ELF 64-bit LSB executable, UCB RISC-V, RVC, double-float ABI, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-riscv64-lp64d.so.1, for GNU/Linux 4.15.0, not stripped
```

We likely need to amend the gcc configuration commands to include something like `--with-sysroot=/opt/riscvx/sysroot`, then repeat the
build.

There are some key questions to consider before we start down this path:

* when is the gcc-14 toolchain 'good enough'?  It almost certainly needs to be able to find a workable `usr/include` and to generate
  a ELF file that *looks* executable on a 64 bit RISCV linux system.
* can we guarantee hermeticity - that is, show that the host Fedora 39 system's /usr/include is never referenced during a RISCV gcc-14 build?
* where do the files under ``.../sysroot` come from?  Some likely come from a kernel build, some from the gcc build
  and some from the glibc build.  The gcc and glibc builds have mutual dependencies.  This appears to mean we need a
  partial build and installation of gcc, a full build and installation of glibc, then complete the build and installation of gcc.

## add a sysroot directory to configurations

```console
$ mkdir /opt/riscvx/sysroot
$ cd /home2/build/gcc
/home2/build/gcc$ /home2/vendor/gcc/configure --prefix=/opt/riscvx --enable-languages=c,c++ --disable-multilib --target=riscv64-unknown-linux-gnu --with-sysroot=/opt/riscvx/sysroot
/home2/build/gcc$ make
...
The directory (BUILD_SYSTEM_HEADER_DIR) that should contain system headers does not exist:
  /opt/riscvx/sysroot/usr/include
/home2/build/gcc$ mkdir -p /opt/riscvx/sysroot/usr/include
/home2/build/gcc$ make
...
fatal error: stdio.h: No such file or directory
cp -r /opt/riscv/sysroot/usr/include /opt/riscvx/sysroot/usr/include
/home2/build/gcc$ /home2/vendor/gcc/configure --prefix=/opt/riscvx --enable-languages=c,c++ --disable-multilib --target=riscv64-unknown-linux-gnu --with-sysroot=/opt/riscvx/sysroot
/home2/build/gcc$ make
...
/opt/riscvx/riscv64-unknown-linux-gnu/bin/ld: cannot find -lc: No such file or directory
make install
```

In that sequence we imported the sysroot used by or imported by https://github.com/riscv-collab/riscv-gnu-toolchain

This suggests:

* we need to import a baseline sysroot from a similar system and especially a kernel similar to the one we are notionally building for.
* that sysroot *may* evolve during the gcc and glibc build.
* the sysroot is a part of the system platform description, and should be versioned as such

## Add glibc

```console
/home2/build/glibc$ ../../vendor/glibc/configure --prefix=/opt/riscvx --enable-languages=c,c++ --disable-multilib --target=riscv64-unknown-linux-gnu --with-sysroot=/opt/riscvx/sysroot
/home2/build/glibc$ make
...
cannot find -lgcc: No such file or directory

/home2/build/glibc$ make install
```

Add bootstrap versions of libgcc to sysroot and try with the same configuration options used by the published riscv toolchain:

```
/home2/build/glibc$ ../../vendor/glibc/configure --host=riscv64-unknown-linux-gnu --prefix=/usr --disable-werror --enable-shared --enable-obsolete-rpc --with-headers=/home2/vendor/riscv-gnu-toolchain/linux-headers/include --disable-multilib --enable-kernel=3.0.0 --libdir=/usr/lib libc_cv_slibdir=/lib libc_cv_rtlddir=/lib
/home2/build/glibc$ make
```