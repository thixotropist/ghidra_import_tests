---
title: Notes
linkTitle: Notes
menu: {main: {weight: 50}}
weight: 50
---

{{% pageinfo %}}
Put unstructured comments here until we know what to do with them.
{{% /pageinfo %}}

## TODO

* Collect exemplars that fail Ghidra import into a common directory,
  including material that might help in creating a formal Ghidra issue
  or triaging future research and development initiatives.
* Add toolchain exemplars to generate binaries with Link Time Optimization.
* Add toolchain exemplars where the source uses C++ header modules.
* Update the `isa_ext` Ghidra branch to expand `vsetvli`` arguments 
* Cleanup and annotate the Bazel toolchain framework.
    * mark stanzas that are believed to be currently unused
    * minimize variances between the different toolchains - there are a lot of
      variances that just add confusion, especially involving linking and system root paths.

## Existing scattered documentation to be consolidated here

```text

 6215 Oct 16 06:39 ./Design.md
 9928 Dec 22 14:04 ./Readme.md
 3715 Oct 16 06:27 ./Roadmap.md
 5252 Nov 20 13:08 ./Sidebars.md

```