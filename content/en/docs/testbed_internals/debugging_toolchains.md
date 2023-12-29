---
title: debugging toolchains
weight: 20
---

{{% pageinfo %}}
Debugging toolchains can be tedious
{{% /pageinfo %}}

Suppose you wanted to build a gcc-14 toolchain with the latest glibc standard libraries, and you were using a Linux host with gcc-13 and reasonably
current glibc standard libraries.  How would you gurantee that none of your older host files were accidentally used where you expected
the newer gcc and glibc files to be used?

Bazel enforces this *hermeticity* by running all toolchain steps in a sandbox, where only declared dependencies of the toolchain components
are visible.  That means nothing under /usr or $HOME is generally available, and any attempt to access files there will abort the build.

Example:

```console
ERROR: /home/XXX/projects/github/ghidra_import_tests/x86_64/toolchain/userSpaceSamples/BUILD:3:10: Compiling userSpaceSamples/helloworld.c failed: absolute path inclusion(s) found in rule '//userSpaceSamples:helloworld':
the source file 'userSpaceSamples/helloworld.c' includes the following non-builtin files with absolute paths (if these are builtin files, make sure these paths are in your toolchain):
  '/usr/include/stdc-predef.h'
  '/usr/include/stdio.h'
```

In this example the toolchain tried to load host files, where it should have been loading equivalent files from the toolchain tarball.
