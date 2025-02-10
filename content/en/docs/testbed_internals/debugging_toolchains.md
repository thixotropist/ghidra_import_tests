---
title: debugging toolchains
weight: 20
---

{{% pageinfo %}}
Debugging toolchains can be tedious
{{% /pageinfo %}}

Suppose you wanted to build a gcc-14 toolchain with the latest glibc standard libraries, and you were using a Linux host with gcc-14 and reasonably
current glibc standard libraries.  How would you guarantee that none of your older host files were accidentally used where you expected
the newer gcc and glibc files to be used?

Bazel enforces this *hermeticity* by running all toolchain steps in a sandbox, where only declared dependencies of the toolchain components
are visible.  That means nothing under /usr or $HOME is generally available, and any attempt to access files there will abort the build.

Example:

```console
ERROR: /home/XXX/projects/github/ghidra_import_tests/x86_64/generated/userSpaceSamples/BUILD:3:10: Compiling userSpaceSamples/helloworld.c failed: absolute path inclusion(s) found in rule '//userSpaceSamples:helloworld':
the source file 'userSpaceSamples/helloworld.c' includes the following non-builtin files with absolute paths (if these are builtin files, make sure these paths are in your toolchain):
  '/usr/include/stdc-predef.h'
  '/usr/include/stdio.h'
```

In this example the toolchain tried to load host files, where it should have been loading equivalent files from the toolchain tarball.

## Toolchain failure modes

Bazel toolchains should provide and encapsulate *almost* everything host computers need to compile and link executables.  The goal is simply to minimize toolchain differences
between individual developers' workstations and the reference Continuous Integration test servers.  The toolchains do not include kernels or loaders, or system code tightly
associated with the kernel.  That presents a challenge, since we want the linker to be imported as part of the toolchain, while the system loader is provided by the host.

Common toolchain failure modes often show up during crosscompilation of something as simple as `riscv64-unknown-linux-gnu-gcc helloworld.c`.

* The `gcc` compiler must find the compiler dynamic libraries it was compiled with, probably using `LD_LIBRARY_PATH` to find them.
    * These include compiler-specific files like `libstdc++.so.6` which links to concrete versions like `libstdc++.so.6.0.32`.
	* These libraries must be part of the imported toolchain tarball and explicitly named as Bazel toolchain dependencies so that they are imported into the 'sandbox' isolating the build
	  from system libraries
	* Other host-specific loader files should not be part of the toolchain tarball.  These include the dynamic loader `ld-linux-x86-64.so.2`
* The `gcc` executable must find and execute multiple other executables from the toolchain, such as `cpp`, `as`, and `ld`.
    * These should *not* be the same executables as may be provided by the native host system
    * Each of these other executables must find their own dependencies, never the host system's files of similar name.
* Many of the toughest problems surface during the linking phase of crosscompilation, where `gcc` internally invokes the linker `ld`.
    * `ld` executes on the host computer - we assume an x86_64 linux system - which means it needs an x86_64 `libc.so` library from the toolchain.  It also generally needs to link
	  object files against the target platform's `libc.so` library from a different library in the toolchain.
	* `ld` also often needs files specific to the target system's kernel or loader.  These include files like `usr/lib/crt1.o`.
	* `ld` accepts many arguments detailing the target system's memory model.  Different arguments cause the linker to require different linker scripts under `.../ldscripts`.
	* `ld` sharable object files can be scripts referencing other libraries - and those references may be absolute, not relative.  These scripts may need to be patched so that
	  host paths are not followed.

Compiler developers often refactor their dependent file layouts, making it very easy to not have required files in the expected places.  You will generally get a useful error message if
something like `crt1.o` isn't located.  If a dynamic library is not found in a child process, you might just get a segfault.

The debugging process often proceeds with:

1. A python integration test script showing multiple toolchain Bazel failures
2. Isolate and execute a single failing relatively simple Bazel build operation
3. Add Bazel diagnostics to the build command, such as `--sandbox_debug`
4. Locate the Bazel sandbox created for that build command and execute the `gcc` command directly
5. Check the sandbox to verify that key files are available within the sandbox, not just present in the imported toolchain tarball
6. Execute the `gcc` command within an `strace` command, with options to follow child processes and expand strings. Examine `execve` and `open` system calls to verify that imported files
   are found before host system files, and that the imported files are actually in a searched directory

### Bazel segment faults after upgrade

The crosscompiler toolchain assumes that *all* files needed for a build are known to the Bazel build system.  This assumption often breaks
when upgrading a compiler or OS.  This example shows what can happen when updating the host OS from Fedora 39 to Fedora 40. 

The relevant integration test is `generateInternalExemplars.py`:

```console
$ ./generateInternalExemplars.py
...
FAIL: test_03_riscv64_build (__main__.T0BazelEnvironment.test_03_riscv64_build)
riscV64 C build of helloworld, with checks to see if a compatible toolchain was
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/home/thixotropist/projects/github/ghidra_import_tests/./generateInternalExemplars.py", line 58, in test_03_riscv64_build
    self.assertEqual(0, result.returncode,
AssertionError: 0 != 1 : bazel //platforms:riscv_userspace build of userSpaceSamples:helloworld failed
...
Ran 8 tests in 6.290s

FAILED (failures=5)
```

The error log is large, showing 5 failures out of 8 tests. We will narrow the test to a single test case:

```console
$ python  ./generateInternalExemplars.py T0BazelEnvironment.test_03_riscv64_build
INFO:root:Running: bazel --noworkspace_rc --output_base=/run/user/1000/bazel build -s --distdir=/opt/bazel/distdir --incompatible_enable_cc_toolchain_resolution --experimental_enable_bzlmod --incompatible_sandbox_hermetic_tmp=false --save_temps --platforms=//platforms:riscv_userspace --compilation_mode=dbg userSpaceSamples:helloworld
...
ERROR: /home/thixotropist/projects/github/ghidra_import_tests/riscv64/generated/userSpaceSamples/BUILD:3:10: Compiling userSpaceSamples/helloworld.c failed: (Segmentation fault): gcc failed: error executing CppCompile command (from target //userSpaceSamples:helloworld) toolchains/gcc-14-riscv/imported/gcc -U_FORTIFY_SOURCE '--sysroot=external/gcc-14-riscv64-suite/sysroot' -Wall -g -MD -MF bazel-out/k8-dbg/bin/userSpaceSamples/_objs/helloworld/helloworld.pic.s.d ... (remaining 20 arguments skipped)

Use --sandbox_debug to see verbose messages from the sandbox and retain the sandbox build root for debugging
toolchains/gcc-14-riscv/imported/gcc: line 5:     4 Segmentation fault      (core dumped) PATH=`pwd`/toolchains/gcc-14-riscv/imported LD_LIBRARY_PATH=external/fedora39-system-libs external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-gcc "$@"
ERROR: /home/thixotropist/projects/github/ghidra_import_tests/riscv64/generated/userSpaceSamples/BUILD:3:10: Compiling userSpaceSamples/helloworld.c failed: (Segmentation fault): gcc failed: error executing CppCompile command (from target //userSpaceSamples:helloworld) toolchains/gcc-14-riscv/imported/gcc -U_FORTIFY_SOURCE '--sysroot=external/gcc-14-riscv64-suite/sysroot' -Wall -g -MD -MF bazel-out/k8-dbg/bin/userSpaceSamples/_objs/helloworld/helloworld.pic.i.d ... (remaining 20 arguments skipped)

Use --sandbox_debug to see verbose messages from the sandbox and retain the sandbox build root for debugging
toolchains/gcc-14-riscv/imported/gcc: line 5:     4 Segmentation fault      (core dumped) PATH=`pwd`/toolchains/gcc-14-riscv/imported LD_LIBRARY_PATH=external/fedora39-system-libs external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-gcc "$@"
ERROR: /home/thixotropist/projects/github/ghidra_import_tests/riscv64/generated/userSpaceSamples/BUILD:3:10: Compiling userSpaceSamples/helloworld.c failed: (Segmentation fault): gcc failed: error executing CppCompile command (from target //userSpaceSamples:helloworld) toolchains/gcc-14-riscv/imported/gcc -U_FORTIFY_SOURCE '--sysroot=external/gcc-14-riscv64-suite/sysroot' -Wall -g -MD -MF bazel-out/k8-dbg/bin/userSpaceSamples/_objs/helloworld/helloworld.pic.d ... (remaining 19 arguments skipped)
```

The three segment fault dumps can be found in `/var/lib/systemd/coredump/`.

The ERROR message indicates segment faults when generating three dependency listings.  To drill down further we want to use take the `Use --sandbox_debug` hint and run the single bazel
build command:

```console
$  cd riscv64/generated/
riscv64/generated $ bazel --noworkspace_rc --output_base=/run/user/1000/bazel build -s --sandbox_debug --distdir=/opt/bazel/distdir --incompatible_enable_cc_toolchain_resolution --experimental_enable_bzlmod --incompatible_sandbox_hermetic_tmp=false --save_temps --platforms=//platforms:riscv_userspace --compilation_mode=dbg userSpaceSamples:helloworld
...
ERROR: /home/thixotropist/projects/github/ghidra_import_tests/riscv64/generated/userSpaceSamples/BUILD:3:10: Compiling userSpaceSamples/helloworld.c failed: (Segmentation fault): linux-sandbox failed: error executing CppCompile command 
  (cd /run/user/1000/bazel/sandbox/linux-sandbox/4/execroot/_main && \
  exec env - \
    PATH=/home/thixotropist/.local/bin:/home/thixotropist/bin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/var/lib/snapd/snap/bin:/home/thixotropist/.local/bin:/home/thixotropist/bin:/opt/ghidra_11.1_DEV/:/home/thixotropist/.cargo/bin::/usr/lib/jvm/jdk-17-oracle-x64/bin:/opt/gradle-7.6.2/bin \
    PWD=/proc/self/cwd \
    TMPDIR=/tmp \
  /home/thixotropist/.cache/bazel/_bazel_thixotropist/install/80f400a450641cd3dd880bb8dec91ff8/linux-sandbox -t 15 -w /dev/shm -w /run/user/1000/bazel/sandbox/linux-sandbox/4/execroot/_main -w /tmp -S /run/user/1000/bazel/sandbox/linux-sandbox/4/stats.out -D /run/user/1000/bazel/sandbox/linux-sandbox/4/debug.out -- toolchains/gcc-14-riscv/imported/gcc -U_FORTIFY_SOURCE '--sysroot=external/gcc-14-riscv64-suite/sysroot' -Wall -g -MD -MF bazel-out/k8-dbg/bin/userSpaceSamples/_objs/helloworld/helloworld.pic.i.d '-frandom-seed=bazel-out/k8-dbg/bin/userSpaceSamples/_objs/helloworld/helloworld.pic.i' -fPIC -iquote . -iquote bazel-out/k8-dbg/bin -iquote external/bazel_tools -iquote bazel-out/k8-dbg/bin/external/bazel_tools -fno-canonical-system-headers -Wno-builtin-macro-redefined '-D__DATE__="redacted"' '-D__TIMESTAMP__="redacted"' '-D__TIME__="redacted"' -c userSpaceSamples/helloworld.c -E -o bazel-out/k8-dbg/bin/userSpaceSamples/_objs/helloworld/helloworld.pic.i)
toolchains/gcc-14-riscv/imported/gcc: line 5:     4 Segmentation fault      (core dumped) PATH=`pwd`/toolchains/gcc-14-riscv/imported LD_LIBRARY_PATH=external/fedora39-system-libs external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-gcc "$@"
```

This tells us several things:

* the failing command is trying to generate `helloworld.pic.i` from `userSpaceSamples/helloworld.c` with the gcc flag `-E`.  This means the failure involves the preprocessor phase, not the compiler or linker phase.
* the failing command is executing in the sandbox directory `/run/user/1000/bazel/sandbox/linux-sandbox/4`.

The next step is to rerun the generated command outside of bazel, but using the bazel sandbox.

```console
$ pushd /run/user/1000/bazel/sandbox/linux-sandbox/4/execroot/_main
$ toolchains/gcc-14-riscv/imported/gcc -U_FORTIFY_SOURCE '--sysroot=external/gcc-14-riscv64-suite/sysroot' -Wall -g -MD -MF bazel-out/k8-dbg/bin/userSpaceSamples/_objs/helloworld/helloworld.pic.i.d '-frandom-seed=bazel-out/k8-dbg/bin/userSpaceSamples/_objs/helloworld/helloworld.pic.i' -fPIC -iquote . -iquote bazel-out/k8-dbg/bin -iquote external/bazel_tools -iquote bazel-out/k8-dbg/bin/external/bazel_tools -fno-canonical-system-headers -Wno-builtin-macro-redefined '-D__DATE__="redacted"' '-D__TIMESTAMP__="redacted"' '-D__TIME__="redacted"' -c userSpaceSamples/helloworld.c -E -o bazel-out/k8-dbg/bin/userSpaceSamples/_objs/helloworld/helloworld.pic.i
toolchains/gcc-14-riscv/imported/gcc: line 5: 552557 Segmentation fault      (core dumped) PATH=`pwd`/toolchains/gcc-14-riscv/imported LD_LIBRARY_PATH=external/fedora39-system-libs external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-gcc "$@"
$ cat toolchains/gcc-14-riscv/imported/gcc
#!/bin/bash
set -euo pipefail
PATH=`pwd`/toolchains/gcc-14-riscv/imported \
LD_LIBRARY_PATH=external/fedora39-system-libs \
  external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-gcc "$@"
$ ls -l external/gcc-14-riscv64-suite/bin
total 0
riscv64-unknown-linux-gnu-ar -> /run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-ar
riscv64-unknown-linux-gnu-as -> /run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-as
riscv64-unknown-linux-gnu-cpp -> /run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-cpp
riscv64-unknown-linux-gnu-gcc -> /run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-gcc
riscv64-unknown-linux-gnu-ld -> /run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-ld
riscv64-unknown-linux-gnu-ld.bfd -> /run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-ld.bfd
riscv64-unknown-linux-gnu-objdump -> /run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-objdump
riscv64-unknown-linux-gnu-ranlib -> /run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-ranlib
riscv64-unknown-linux-gnu-strip -> /run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-strip

$ ls -l external/fedora39-system-libs
total 0
libc.so -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libc.so
libc.so.6 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libc.so.6
libexpat.so.1 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libexpat.so.1
libexpat.so.1.8.10 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libexpat.so.1.8.10
libgcc_s-13-20231205.so.1 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libgcc_s-13-20231205.so.1
libgcc_s.so.1 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libgcc_s.so.1
libgmp.so.10 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libgmp.so.10
libgmp.so.10.4.1 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libgmp.so.10.4.1
libisl.so.15 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libisl.so.15
libisl.so.15.1.1 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libisl.so.15.1.1
libmpc.so.3 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libmpc.so.3
libmpc.so.3.3.1 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libmpc.so.3.3.1
libmpfr.so.6 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libmpfr.so.6
libmpfr.so.6.2.0 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libmpfr.so.6.2.0
libm.so.6 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libm.so.6
libpython3.12.so -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libpython3.12.so
libpython3.12.so.1.0 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libpython3.12.so.1.0
libpython3.so -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libpython3.so
libstdc++.so.6 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libstdc++.so.6
libstdc++.so.6.0.32 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libstdc++.so.6.0.32
libz.so.1 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libz.so.1
libz.so.1.2.13 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libz.so.1.2.13
libzstd.so.1 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libzstd.so.1
libzstd.so.1.5.5 -> /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libzstd.so.1.5.5
```

This suggests a missing or out-of-date sharable library, so try executing cpp with and without overriding the library path

```console
$ LD_LIBRARY_PATH=external/fedora39-system-libs /run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-cpp --version
Segmentation fault (core dumped)
$ /run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-cpp --version
riscv64-unknown-linux-gnu-cpp (g3f23fa7e74f) 13.2.1 20230901
Copyright (C) 2023 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```

Next see which libraries are required for `cpp` to execute:

```console
$ ldd /run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-cpp
	linux-vdso.so.1 (0x00007ffdb7172000)
	libstdc++.so.6 => /lib64/libstdc++.so.6 (0x00007faf79200000)
	libm.so.6 => /lib64/libm.so.6 (0x00007faf7911d000)
	libgcc_s.so.1 => /lib64/libgcc_s.so.1 (0x00007faf794ff000)
	libc.so.6 => /lib64/libc.so.6 (0x00007faf78f30000)
	/lib64/ld-linux-x86-64.so.2 (0x00007faf79547000)
```

Is this a case of a missing library, or something corrupt in our imported `fedora39-system-libs`?
Try a differential test in which we search both libraries, in different orders:

```console
$ LD_LIBRARY_PATH=/lib64/:/run/user/1000/bazel/execroot/_main/external/fedora39-system-libs ldd /run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-cpp
	linux-vdso.so.1 (0x00007ffeb2b92000)
	libstdc++.so.6 => /lib64/libstdc++.so.6 (0x00007fda32200000)
	libm.so.6 => /lib64/libm.so.6 (0x00007fda3211d000)
	libgcc_s.so.1 => /lib64/libgcc_s.so.1 (0x00007fda324a7000)
	libc.so.6 => /lib64/libc.so.6 (0x00007fda31f30000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fda324d6000)
$  LD_LIBRARY_PATH=/run/user/1000/bazel/execroot/_main/external/fedora39-system-libs:/lib64 ldd /run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-cpp
Segmentation fault (core dumped)
```

We can trace the library and child process actions with commands like:

```console
$ strace -f --string-limit=1000 ldd /run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-cpp 2>&1 |egrep 'openat|execve'
execve("/usr/bin/ldd", ["ldd", "/run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-cpp"], 0x7ffcd3479788 /* 54 vars */) = 0
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/lib64/libtinfo.so.6", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/lib64/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/dev/tty", O_RDWR|O_NONBLOCK) = 3
openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib64/gconv/gconv-modules.cache", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/bin/ldd", O_RDONLY) = 3
openat(AT_FDCWD, "/usr/share/locale/locale.alias", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/share/locale/en_US.UTF-8/LC_MESSAGES/libc.mo", O_RDONLY) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/share/locale/en_US.utf8/LC_MESSAGES/libc.mo", O_RDONLY) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/share/locale/en_US/LC_MESSAGES/libc.mo", O_RDONLY) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/share/locale/en.UTF-8/LC_MESSAGES/libc.mo", O_RDONLY) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/share/locale/en.utf8/LC_MESSAGES/libc.mo", O_RDONLY) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/share/locale/en/LC_MESSAGES/libc.mo", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 595197] execve("/lib64/ld-linux-x86-64.so.2", ["/lib64/ld-linux-x86-64.so.2", "--verify", "/run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-cpp"], 0x56317c32bf10 /* 54 vars */) = 0
[pid 595197] openat(AT_FDCWD, "/run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-cpp", O_RDONLY|O_CLOEXEC) = 3
[pid 595200] execve("/lib64/ld-linux-x86-64.so.2", ["/lib64/ld-linux-x86-64.so.2", "/run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-cpp"], 0x56317c339130 /* 58 vars */) = 0
[pid 595200] openat(AT_FDCWD, "/run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-cpp", O_RDONLY|O_CLOEXEC) = 3
[pid 595200] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[pid 595200] openat(AT_FDCWD, "/lib64/libstdc++.so.6", O_RDONLY|O_CLOEXEC) = 3
[pid 595200] openat(AT_FDCWD, "/lib64/libm.so.6", O_RDONLY|O_CLOEXEC) = 3
[pid 595200] openat(AT_FDCWD, "/lib64/libgcc_s.so.1", O_RDONLY|O_CLOEXEC) = 3
[pid 595200] openat(AT_FDCWD, "/lib64/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
```

Examine the imported `fedora39-system-libs` directory, finding one significant error.  The file `libc.so` is not a symbolic link but a loader script, referencing
the host's `/lib64/libc.so.6`, `/usr/lib64/libc_nonshared.a`, and `/lib64/ld-linux-x86-64.so.2`.  If we purge `libc.*` from `fedora39-system-libs` we get a saner result:

```console
$ LD_LIBRARY_PATH=/run/user/1000/bazel/execroot/_main/external/fedora39-system-libs:/lib64 ldd /run/user/1000/bazel/execroot/_main/external/gcc-14-riscv64-suite/bin/riscv64-unknown-linux-gnu-cpp 2>&1 
	linux-vdso.so.1 (0x00007ffda9fed000)
	libstdc++.so.6 => /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libstdc++.so.6 (0x00007f0c1c45a000)
	libm.so.6 => /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libm.so.6 (0x00007f0c1c379000)
	libgcc_s.so.1 => /run/user/1000/bazel/execroot/_main/external/fedora39-system-libs/libgcc_s.so.1 (0x00007f0c1c355000)
	libc.so.6 => /lib64/libc.so.6 (0x00007f0c1c168000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f0c1c6b0000)
```

Now we have a hermeticity design question to resolve - which system libraries do we import, and which do we pull from the host machine?  This exercise suggests we use the host libraries
for dynamic loading *and* for the standard C `libc.so`, and import libraries associated with the C and C++ compiler.

Update the `LD_LIBRARY_PATH` variable in *all* toolchain scripts and explicitly remove libc.* files from the system libraries, then try repeat the failing tests:

```console
$ ./generateInternalExemplars.py 
INFO:root:Running: bazel --noworkspace_rc --output_base=/run/user/1000/bazel build -s --distdir=/opt/bazel/distdir --incompatible_enable_cc_toolchain_resolution --experimental_enable_bzlmod --incompatible_sandbox_hermetic_tmp=false --save_temps --platforms=@local_config_platform//:host --compilation_mode=dbg userSpaceSamples:helloworld
.INFO:root:Running: bazel query //platforms:*
.INFO:root:Running: bazel --noworkspace_rc --output_base=/run/user/1000/bazel build -s --distdir=/opt/bazel/distdir --incompatible_enable_cc_toolchain_resolution --experimental_enable_bzlmod --incompatible_sandbox_hermetic_tmp=false --save_temps --platforms=//platforms:riscv_userspace --compilation_mode=dbg userSpaceSamples:helloworld
INFO:root:Running: file bazel-bin/userSpaceSamples/_objs/helloworld/helloworld.pic.o
.INFO:root:Running: bazel --noworkspace_rc --output_base=/run/user/1000/bazel build -s --distdir=/opt/bazel/distdir --incompatible_enable_cc_toolchain_resolution --experimental_enable_bzlmod --incompatible_sandbox_hermetic_tmp=false --save_temps --platforms=//platforms:riscv_userspace --compilation_mode=dbg userSpaceSamples:helloworld++
INFO:root:Running: file bazel-bin/userSpaceSamples/_objs/helloworld++/helloworld.pic.o
.INFO:root:Running: bazel --noworkspace_rc --output_base=/run/user/1000/bazel build -s --distdir=/opt/bazel/distdir --incompatible_enable_cc_toolchain_resolution --experimental_enable_bzlmod --incompatible_sandbox_hermetic_tmp=false --save_temps --platforms=//platforms:riscv64_thead assemblySamples:archive
.INFO:root:Running: bazel --noworkspace_rc --output_base=/run/user/1000/bazel build -s --distdir=/opt/bazel/distdir --incompatible_enable_cc_toolchain_resolution --experimental_enable_bzlmod --incompatible_sandbox_hermetic_tmp=false --save_temps --platforms=//platforms:riscv64_thead gcc_expansions:archive
.INFO:root:Running: bazel --noworkspace_rc --output_base=/run/user/1000/bazel build -s --distdir=/opt/bazel/distdir --incompatible_enable_cc_toolchain_resolution --experimental_enable_bzlmod --incompatible_sandbox_hermetic_tmp=false --save_temps --platforms=//platforms:riscv64_thead @whisper_cpp//:main @whisper_cpp//:main.stripped
INFO:root:Running: bazel --noworkspace_rc --output_base=/run/user/1000/bazel build -s --distdir=/opt/bazel/distdir --incompatible_enable_cc_toolchain_resolution --experimental_enable_bzlmod --incompatible_sandbox_hermetic_tmp=false --save_temps --platforms=//platforms:riscv_vector @whisper_cpp//:main @whisper_cpp//:main.stripped
INFO:root:Running: bazel --noworkspace_rc --output_base=/run/user/1000/bazel build -s --distdir=/opt/bazel/distdir --incompatible_enable_cc_toolchain_resolution --experimental_enable_bzlmod --incompatible_sandbox_hermetic_tmp=false --save_temps --platforms=//platforms:riscv_userspace @whisper_cpp//:main @whisper_cpp//:main.stripped
.INFO:root:Running: bazel --noworkspace_rc --output_base=/run/user/1000/bazel build -s --distdir=/opt/bazel/distdir --incompatible_enable_cc_toolchain_resolution --experimental_enable_bzlmod --incompatible_sandbox_hermetic_tmp=false --save_temps --platforms=//platforms:x86_64_default gcc_vectorization:archive
.
----------------------------------------------------------------------
Ran 8 tests in 61.357s

OK
```
