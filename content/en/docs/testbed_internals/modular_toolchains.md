---
title: modular toolchains
weight: 40
---

We would like to use Bazel's module system to move much of the compiler suite code
out of the current workspace.  Parts of the crosscompiler toolchain will remain
in the workspace, such as platform definitions and compiler/linker options specific to the project.
The compilers, linkers, and supporting libraries can be extracted.

## Design

We start with a workspace that includes all gcc 14.1.0 compiler suite components.  The workspace
integration test `./generateInternalExemplars.py` passes.  The goal is continue passing this test after:

* remove the top level `riscv64` directory holding the gcc 14.1.0 compiler suite.
* import the gcc 14.1.0 `riscv64` compiler suite from an external repo using Bazel's bzlmod infrastructure.
* add a gcc 15.0.0 `riscv64` compiler suite.
* show that the integration test passes with either version of the gcc module imported.

Assumptions:

1. this project will use only one version of the `gcc_riscv` module at a time.
2. maintenance and evolution of the Bazel modules is handled in a separate project.

### Workspace

The gcc compiler suite and its Fedora system dependencies should be imported as versioned modules.
We start with gcc_riscv versions 14.1.0 and 15.0.0(unreleased).  Each of these has a transitive dependency
on several Fedora 40 system libraries.

In a development lab environment we would use a remote Bazel module repository.  Here we use
a local one, under `/opt/bazel/bzlmod`.  This local repo can be added to the global Bazel repo by adding
these lines to `.bazelrc`:

```text
# Add global registry
common --registry https://bcr.bazel.build
# Add local registry
common --registry file:///opt/bazel/bzlmod
```

We can import the gcc_riscv module and its dependencies with an addition to `MODULE.bazel`:

```text
bazel_dep(name="fedora_syslibs", version="40.0.0")
bazel_dep(name="gcc_riscv_suite", version="14.1.0")
```

>Note: Bazel will normally handle transitive dependencies like `fedora_syslibs` on its own.
>      We need to add this one explicitly since the toolchain wrapper scripts need to know the
>      library locations.

### Modules

* Each compiler suite includes `gcc`, `binutils`, `glibc`, and a generic `sysroot`.
* We maintain two versions of each suite, the most recent released version and a developmental,
  unreleased version.
* external compiler suite source code is found under `/home2/vendor/{binutils-gdb,gcc,glibc}`
* external compiler suite builds are completed under `/home2/build$arch/{binutils,gcc,glibc}`
* external compiler suite installs for riscv go to `/opt/riscv*/sysroot`.
* files selected from `/opt/riscv*/sysroot` are copied into `/opt/bazel/bzlmod/src/gcc_riscv_suite`
* `/opt/bazel/bzlmod/src/gcc_riscv_suite` is post-processed to strip binaries, remove duplicates,
  generating a compressed tarball usable by Bazel's bzlmod system.

