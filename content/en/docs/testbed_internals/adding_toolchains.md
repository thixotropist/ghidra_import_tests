---
title: adding toolchains
weight: 10
---

{{% pageinfo %}}
Adding a new toolchain takes lots of little steps, and some trial and error.
{{% /pageinfo %}}

## Overview

We want x86_64 exemplars built with the same next generation of gcc, libc, and libstdc++ as
we use for RISCV exemplars.  This will give us some hints about how common new issues may
be and how global new solutions may need to be.

We will generate this x86_64 gcc-14 toolchain about the same way as our existing riscv-64 gcc-14 toolchain.

This example uses the latest released version of binutils and the development head of gcc and glibc.

If we were building a toolchain for an actual product we would start by configuring and building
a specialized kernel, which would prepopulate the system root.  We aren't doing that here, so
we will use placeholders from the Fedora 39 x86_64 kernel.

## binutils and the first gcc pass

We want binutils installed first.

```console
$ cd /home2/vendor/binutils-gdb
$ git log
commit 2c73aeb8d2e02de7b69cbcb13361cfbca9d76a4e (HEAD, tag: binutils-2_41)
Author: Nick Clifton <nickc@redhat.com>
Date:   Sun Jul 30 14:55:52 2023 +0100

    The 2.41 release!
...
$ cd /home2/build_x86/binutils
.../vendor/binutils-gdb/configure --prefix=/opt/gcc14 --disable-multilib --enable-languages=c,c++,rust,lto
...
$ make
$ make install
...
```

The gcc suite and the glibc standard library have a circular dependency.  We build and install
the basic gcc capability first, then glibc, and then finish with the rest of gcc.  During this process
we likely need to add system files to the new sysroot directory.

```console
$ cd /home2/vendor/gcc
$ git log
commit ac9c81dd76cfc34ed53402049021689a61c6d6e7 (HEAD -> master, origin/trunk, origin/master, origin/HEAD)
Author: Pan Li <pan2.li@intel.com>
Date:   Mon Dec 18 21:40:00 2023 +0800

    RISC-V: Rename the rvv test case.
...
$ cd /home2/build_x86/gcc
/home2/vendor/gcc/configure --prefix=/opt/gcc14 --disable-multilib --enable-languages=c,c++,rust,lto
$ make
...
$ make install
...
```

The `make` and `make install` may throw errors after completing the basic compiler.  If so, we can
complete the build after we get glibc installed.

## glibc

We should have enough of gcc-14 built to configure and build the 64 bit glibc package.  This pending release of glibc
has lots of changes, so we can expect some tinkering to get it to work for us.

```console

$ cd /home2/vendor/glibc
$ git log
commit e957308723ac2e55dad360d602298632980bbd38 (HEAD -> master, origin/master, origin/HEAD)
Author: Matthew Sterrett <matthew.sterrett@intel.com>
Date:   Fri Dec 15 12:04:05 2023 -0800

    x86: Unifies 'strlen-evex' and 'strlen-evex512' implementations.
...
$ mkdir -p /home2/build_x86/glibc
$ cd /home2/build_x86/glibc
$ /home2/vendor/glibc/configure CC="/opt/gcc14/bin/gcc" --prefix="/usr" install_root=/opt/gcc14/sysroot --disable-werror --enable-shared --disable-multilib
$ make
$ make install_root=/opt/gcc14/sysroot install
$ du -hs /opt/gcc14/sysroot
105M	/opt/gcc14/sysroot
```

## gcc finish

If the `gcc` installation errored out before completion, try it again after glibc is installed.  This time it should complete without error.

## testing the local toolchain

Next we want to exercise the toolchain by compiling a very simple C program:

```c
#include <stdio.h>
int main(int argc, char** argv){
    const int N = 1320;
    char s[N];
    for (int i = 0; i < N - 1; ++i)
        s[i] = i + 1;
    s[N - 1] = '\0';
    printf(s);
}
```

We'll build it with three sets of options and import all three into Ghidra 11

```console
/opt/gcc14/bin/gcc gcc_vectorization/helloworld_challenge.c -o a_unoptimized.out
/opt/gcc14/bin/gcc -O3 gcc_vectorization/helloworld_challenge.c -o a_host_optimized.out
/opt/gcc14/bin/gcc -march=rocketlake -O3 gcc_vectorization/helloworld_challenge.c -o a_rocketlake_optimized.out
```

>Note: Rocket Lake is Intel's codename for its 11th generation Core microprocessors

Ghidra 11 gives us:

* `a_unoptimized.out` imports and decompiles cleanly, with recognizable disassembly and decompiler output of 5 lines of code.
* `a_host_optimized.out` imports cleanly and decompiles into about 150 lines of hard-to-interpret C code.  The loop has been
  autovectorized using instructions like `PUNPCKHWD`, `PUNPCKLWD`, and `PADDD`.  These appear to be AVX-512 vector extensions.
* `a_rocketlake_optimized.out` fails to disassemble *or* decompile when it hits AVX2 instructions like `vpbroadcastd`.
  Binutils 2.41's `objdump` appears to recognize these instructions.

As a stretch goal, what does the gcc-14 Rust compiler give us?

```console
/opt/gcc14/bin/gccrs -frust-incomplete-and-experimental-compiler-do-not-use src/main.rs
src/main.rs:25:5: error: unknown macro: [log::info]
   25 |     log::info!(
      |     ^~~
src/main.rs:29:5: error: unknown macro: [log::info]
   29 |     log::info!(
      |     ^~~
...
```

If gccrs can't handle basic rust macros, it isn't very useful for generating exemplars.  We won't include it in our portable toolchain.

## packaging the toolchain

Now we need to make the toolchain hermetic, portable, and ready for Bazel workspaces.

Hermeticity means that nothing under `/opt/gcc14` makes a hidden reference to local host files under `/usr`.  Any such reference needs to
be changed into a relative reference.  These are common in short sharable object files that link to one or more true sharable object libraries.

You can often identify possible troublemakers by searching for smallish regular files with a `.so` extension.  

```console
$ find /opt/gcc14 -name \*.so -type f -size -1000c -ls
/opt/gcc14$ find /opt/gcc14 -name \*.so -type f -size -1000c -ls
... 273 Dec 27 12:41 /opt/gcc14/lib/libc.so
... 126 Dec 27 12:42 /opt/gcc14/lib/libm.so
... 132 Dec 27 11:42 /opt/gcc14/lib64/libgcc_s.so

$ cat /opt/gcc14/lib/libc.so
/* GNU ld script
   Use the shared library, but some functions are only in
   the static library, so try that secondarily.  */
OUTPUT_FORMAT(elf64-x86-64)
GROUP ( /opt/gcc14/lib/libc.so.6 /opt/gcc14/lib/libc_nonshared.a  AS_NEEDED ( /opt/gcc14/lib/ld-linux-x86-64.so.2 ) )

$ cat /opt/gcc14/lib/libm.so
/* GNU ld script
*/
OUTPUT_FORMAT(elf64-x86-64)
GROUP ( /opt/gcc14/lib/libm.so.6  AS_NEEDED ( /opt/gcc14/lib/libmvec.so.1 ) )

$ cat /opt/gcc14/lib/libm.so
/* GNU ld script
*/
OUTPUT_FORMAT(elf64-x86-64)
GROUP ( /opt/gcc14/lib/libm.so.6  AS_NEEDED ( /opt/gcc14/lib/libmvec.so.1 ) )
thixotropist@mini:/opt/gcc14$ cat /opt/gcc14/lib64/libgcc_s.so
/* GNU ld script
   Use the shared library, but some functions are only in
   the static library.  */
GROUP ( libgcc_s.so.1 -lgcc )

```

So two of the three files need patching: replacing `/opt/gcc14/lib` with `.`.  Any text editor will do.

Next we need to identify all dynamic host dependencies of binaries under `/opt/gcc14`.
The `ldd` command will identify these local system files,
which should be collected into a separate tarball.  This tarball can be shared with other cross-compilers
built at the same time, and is generally portable across similar linux kernels and distributions.

At this point we can `strip` the executable files within the toolchain and identify the ones we want to keep in the portable toolchain tarball.
Scripts under `toolchain/toolchains/gcc-14-*/scripts` will help with that.

`generate.sh` uses rsync to copy selected files from `/opt/gcc14` into `/tmp/export`, stripping the known binaries, and creating the portable tarball.
It then collects relevant dynamic libraries from the host and creates a second portable tarball.

These two tarballs can then be copied to other computers and imported into a project by adding stanzas to the project WORKSPACE file.

## installing the toolchain

The toolchain tarball is currently in `/opt/bazel``.  We need its full path and sha256sum to make it accessible within our workspace.
Edit `WORKSPACE` to include:

```python
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# gcc-14 x86_64 toolchain from snapshot gcc-14 and glibc development heads
http_archive(
    name = "gcc-14-x86_64-toolchains",
    urls = ["file:///opt/bazel/x86_64_linux_gnu-14.tar.xz"],
    build_file = "//:gcc-14-x86_64-toolchains.BUILD",
    sha256 = "40cc4664a11b8da56478393c7c8b823b54f250192bdc1e1181c9e4f8ac15e3be",
)

# system libraries used by toolchain build system
# We built the custom toolchain on a fedora x86_64 platform, so we need some
# fedora x86_64 sharable system libraries to execute.
http_archive(
    name = "fedora39-system-libs",
    urls = ["file:///opt/bazel/fedora39_system_libs.tar.xz"],
    build_file = "//:fedora39-system-libs.BUILD",
    sha256 = "fe91415b05bb902964f05f7986683b84c70338bf484f23d05f7e8d4096949d1b",
)
```

Bazel will unpack this tarball into an external project directory, something like `/run/user/1000/bazel/execroot/_main/external/gcc-14-x86_64-toolchains/`.
Individual files and filegroups within that directory are defined in `x86_64/toolchain/gcc-14-x86_64-toolchains.BUILD`.
The filegroup `compiler_files` is probably the most important, as it collects everything that might be used in anything launched from gcc or g++.
The full Bazel name for this filegroup is `@gcc-14-x86_64-toolchains//:compiler_files`.

Each custom toolchain is defined within the `x86_64/toolchain/toolchains/BUILD` file.  This associates filegroups from a (possibly shared) toolchain tarball like
`gcc-14-x86_64-toolchains` with a set of default compiler and linker options and standard libraries.  We might want multiple gcc-14 toolchains, for building kernels,
kernel modules, and userspace applications respectively.

Most of the configuration exists within stanzas like this:

```python
toolchain(
    name = "x86_64_default",
    target_compatible_with = [
        ":x86_64",
    ],
    toolchain = ":x86_64-default-gcc",
    toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
)
cc_toolchain(
    name = "x86_64-default-gcc",
    all_files = ":all_files",
    ar_files = ":gcc_14_compiler_files",
    as_files = ":empty",
    compiler_files = ":gcc_14_compiler_files",
    dwp_files = ":empty",
    linker_files = ":gcc_14_compiler_files",
    objcopy_files = ":empty",
    strip_files = ":empty",
    supports_param_files = 0,
    toolchain_config = ":x86_64-default-gcc-config",
    toolchain_identifier = "x86_64-default-gcc",
)
cc_toolchain_config(
    name = "x86_64-default-gcc-config",
    abi_libc_version = ":empty",
    abi_version = ":empty",
    compile_flags = [
        # take the isystem ordering from the output of gcc -xc++ -E -v -
        "--sysroot", "external/gcc-14-x86_64-toolchains/sysroot/",
        "-Wall",
    ],
    compiler = "gcc",
    coverage_compile_flags = ["--coverage"],
    coverage_link_flags = ["--coverage"],
    cpu = "x86_64",
    # we really want the following to be constructed from $(output_base) or $(location ...)
    cxx_builtin_include_directories = [
       OUTPUT_BASE + "/external/gcc-14-x86_64-toolchains/sysroot/usr/include",
       OUTPUT_BASE + "/external/gcc-14-x86_64-toolchains/x86_64-pc-linux-gnu/include/c++/14.0.0",
       OUTPUT_BASE + "/external/gcc-14-x86_64-toolchains/lib/gcc/x86_64-pc-linux-gnu/14.0.0/include",
       OUTPUT_BASE + "/external/gcc-14-x86_64-toolchains/lib/gcc/x86_64-pc-linux-gnu/14.0.0/include-fixed",
       ],
    cxx_flags = [
        "-std=c++20",
        "-fno-rtti",
        ],
    dbg_compile_flags = ["-g"],
    host_system_name = ":empty",
    link_flags = ["--sysroot", "external/gcc-14-x86_64-toolchains/sysroot/"],
    link_libs = ["-lstdc++", "-lm"],
    opt_compile_flags = [
        "-g0",
        "-Os",
        "-DNDEBUG",
        "-ffunction-sections",
        "-fdata-sections",
    ],
    opt_link_flags = ["-Wl,--gc-sections"],
    supports_start_end_lib = False,
    target_libc = ":empty",
    target_system_name = ":empty",
    tool_paths = {
        "ar": "gcc-14-x86_64/imported/ar",
        "ld": "gcc-14-x86_64/imported/ld",
        "cpp": "gcc-14-x86_64/imported/cpp",
        "gcc": "gcc-14-x86_64/imported/gcc",
        "dwp": ":empty",
        "gcov": ":empty",
        "nm": "gcc-14-x86_64/imported/nm",
        "objcopy": "gcc-14-x86_64/imported/objcopy",
        "objdump": "gcc-14-x86_64/imported/objdump",
        "strip": "gcc-14-x86_64/imported/strip",
    },
    toolchain_identifier = "gcc-14-x86_64",
    unfiltered_compile_flags = [
        "-fno-canonical-system-headers",
        "-Wno-builtin-macro-redefined",
        "-D__DATE__=\"redacted\"",
        "-D__TIMESTAMP__=\"redacted\"",
        "-D__TIME__=\"redacted\"",
    ],
)
```

The `tool_paths` element points to small bash scripts needed to launch compiler components like `gcc` and `ar` and `strip`.
These give us the chance to use imported system sharable object libraries rather than the host's sharable object libraries.

```bash
#!/bin/bash
set -euo pipefail
PATH=`pwd`/toolchains/gcc-14-x86_64/imported \
LD_LIBRARY_PATH=external/fedora39-system-libs \
  external/gcc-14-x86_64-toolchains/bin/gcc "$@"
```

## finding the hidden toolchain dependencies

Compiling and linking source files takes many dependent files from `/opt/gcc14`.  The next step is tedious and iterative - we need to prove
that the portable toolchain tarball derived from `/opt/gcc14` never references any file in that directory, or any local host file under `/usr`.
Bazel can do that for us, at the cost of identifying every file or file 'glob' that may be called for each of the toolchain primitives.
It runs the toolchain in a sandbox, forcing an exception on all references not previously declared as dependencies.

This kind of exception looks like this:

```console
ERROR: /home/XXX/projects/github/ghidra_import_tests/x86_64/toolchain/userSpaceSamples/BUILD:3:10: Compiling userSpaceSamples/helloworld.c failed: absolute path inclusion(s) found in rule '//userSpaceSamples:helloworld':
the source file 'userSpaceSamples/helloworld.c' includes the following non-builtin files with absolute paths (if these are builtin files, make sure these paths are in your toolchain):
  '/usr/include/stdc-predef.h'
  '/usr/include/stdio.h'
```

If you see this check:
* whether `stdio.h` was installed in the right directory under `/opt/gcc14`.
* whether `stdio.h` was copied into `/tmp/export` when building the tarball
* whether the instances of `stdio.h` appeared in the appropriate compiler file groups defined in `gcc-14-x86_64-toolchains.BUILD`
* whether those filegroups were properly imported into the Bazel sandbox for your build
* whether the compile_flags for your toolchain tell gcc-14 to search the sandbox for the directories containing `stdio.h`
    ```
    "-isystem", "external/gcc-14-x86_64-toolchains/sysroot/usr/include",
    ```
* whether the link_flags for your toolchain tell gcc-14 to search the sandbox for the directories containing `crt1.o` and `crti.o`

## using the toolchain

We can test our new toolchain with a build of `helloworld`.

```console
x86_64/toolchain$ bazel clean
INFO: Starting clean (this may take a while). Consider using --async if the clean takes more than several minutes.
x86_64/toolchain$ bazel run -s --platforms=//platforms:x86_64_default userSpaceSamples:helloworld
INFO: Analyzed target //userSpaceSamples:helloworld (69 packages loaded, 1538 targets configured).
SUBCOMMAND: # //userSpaceSamples:helloworld [action 'Compiling userSpaceSamples/helloworld.c', configuration: 672d6d72a34879952e2365b9bc032c10f7e50fda380c4b7c8e86b49faa982e8b, execution platform: @@local_config_platform//:host, mnemonic: CppCompile]
(cd /run/user/1000/bazel/execroot/_main && \
  exec env - \
    PATH=/home/thixotropist/.local/bin:/home/thixotropist/bin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/var/lib/snapd/snap/bin:/home/thixotropist/.local/bin:/home/thixotropist/bin:/opt/ghidra_10.3.2_PUBLIC/:/home/thixotropist/.cargo/bin::/usr/lib/jvm/jdk-17-oracle-x64/bin:/opt/gradle-7.6.2/bin \
    PWD=/proc/self/cwd \
  toolchains/gcc-14-x86_64/imported/gcc -U_FORTIFY_SOURCE --sysroot external/gcc-14-x86_64-toolchains/sysroot/ -Wall -MD -MF bazel-out/k8-fastbuild/bin/userSpaceSamples/_objs/helloworld/helloworld.pic.d '-frandom-seed=bazel-out/k8-fastbuild/bin/userSpaceSamples/_objs/helloworld/helloworld.pic.o' -fPIC -iquote . -iquote bazel-out/k8-fastbuild/bin -iquote external/bazel_tools -iquote bazel-out/k8-fastbuild/bin/external/bazel_tools -fno-canonical-system-headers -Wno-builtin-macro-redefined '-D__DATE__="redacted"' '-D__TIMESTAMP__="redacted"' '-D__TIME__="redacted"' -c userSpaceSamples/helloworld.c -o bazel-out/k8-fastbuild/bin/userSpaceSamples/_objs/helloworld/helloworld.pic.o)
# Configuration: 672d6d72a34879952e2365b9bc032c10f7e50fda380c4b7c8e86b49faa982e8b
# Execution platform: @@local_config_platform//:host
SUBCOMMAND: # //userSpaceSamples:helloworld [action 'Linking userSpaceSamples/helloworld', configuration: 672d6d72a34879952e2365b9bc032c10f7e50fda380c4b7c8e86b49faa982e8b, execution platform: @@local_config_platform//:host, mnemonic: CppLink]
(cd /run/user/1000/bazel/execroot/_main && \
  exec env - \
    PATH=/home/thixotropist/.local/bin:/home/thixotropist/bin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/var/lib/snapd/snap/bin:/home/thixotropist/.local/bin:/home/thixotropist/bin:/opt/ghidra_10.3.2_PUBLIC/:/home/thixotropist/.cargo/bin::/usr/lib/jvm/jdk-17-oracle-x64/bin:/opt/gradle-7.6.2/bin \
    PWD=/proc/self/cwd \
  toolchains/gcc-14-x86_64/imported/gcc -o bazel-out/k8-fastbuild/bin/userSpaceSamples/helloworld -Wl,-S --sysroot external/gcc-14-x86_64-toolchains/sysroot/ bazel-out/k8-fastbuild/bin/userSpaceSamples/_objs/helloworld/helloworld.pic.o -lstdc++ -lm)
# Configuration: 672d6d72a34879952e2365b9bc032c10f7e50fda380c4b7c8e86b49faa982e8b
# Execution platform: @@local_config_platform//:host
INFO: Found 1 target...
Target //userSpaceSamples:helloworld up-to-date:
  bazel-bin/userSpaceSamples/helloworld
INFO: Elapsed time: 0.289s, Critical Path: 0.10s
INFO: 6 processes: 4 internal, 2 linux-sandbox.
INFO: Build completed successfully, 6 total actions
INFO: Running command line: bazel-bin/userSpaceSamples/helloworld
Hello World!
$ strings bazel-bin/userSpaceSamples/helloworld|grep -i gcc
GCC: (GNU) 14.0.0 20231218 (experimental)
```

Things to note:
* The command line includes `--platforms=//platforms:x86_64_default` to show we are *not* building for the local host
* `toolchains/gcc-14-x86_64/imported/gcc` is invoked twice, once to compile and once to link
* `--sysroot external/gcc-14-x86_64-toolchains/sysroot` is used twice, to avoid including host files under `/usr`
* The `helloworld` executable happens to execute on the host machine.
* The `helloworld` executable contains no references to gcc-13, the native toolchain on the host machine.

Now try a C++ build:

```console
$ bazel run -s --platforms=//platforms:x86_64_default userSpaceSamples:helloworld++
...
Target //userSpaceSamples:helloworld++ up-to-date:
  bazel-bin/userSpaceSamples/helloworld++
INFO: Elapsed time: 0.589s, Critical Path: 0.51s
INFO: 3 processes: 1 internal, 2 linux-sandbox.
INFO: Build completed successfully, 3 total actions
INFO: Running command line: bazel-bin/userSpaceSamples/helloworld++
Hello World!
```

## cleanup

We've got a working toolchain, but with many dangling links, duplicate files, and unused definitions.
The toolchain files normally provided by a kernel were copied in as needed from the host, with the understanding that we never
really needed runnable applications.

If this were a production environment we would be a lot more careful.  It's not, so we will just summarize some of the areas
that might benefit from such a cleanup.

### /opt/gcc14

This directory is the install target for our binutils, gcc, and glibc builds.

* The overall size is reported as 3.1 GB, inflated somewhat by multiple hardlinks
* `fdupes` reports 2446 duplicate files (in 2136 sets), occupying 200.2 megabytes
* There are six files over 150 MB in size

### /tmp/export

This directory is a subset of `/opt/gcc14`, with many binaries stripped.  The hard links
of `/opt/gcc14`` are lost.

* the overall size is 731 MB
* `fdupes` reports 1010 duplicate files (in 983 sets), occupying 69.0 megabytes
* There are 16 files over 10 MB in size

### /opt/bazel/x86_64_linux_gnu-14.tar.xz

The compressed portable tarball size is 171M.  It expands into a locally cached equivalent of `/tmp/export`.

