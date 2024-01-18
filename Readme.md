# Ghidra binary import tests

>Warning: The primary documentation is now in a Hugo + Docsy static web site.  The material below
>         will eventually be merged into that directory.

Generate the documentation website with `hugo serve` in this directory, then open a browser at http://localhost:1313/ghidra_import_tests/.

## Summary

This project addresses several goals:

* Show how a set of importable binaries can be used as input for Ghidra regression tests.
    * The proof-of-concept example currently provided validates RISCV-64 relocation code handlers within the Ghidra ELF importer.
      The python script `integrationTest.py` is an example of a possible Continuous Integration script.
* Acquire a set of larger Ghidra-importable exemplar binaries *without* exposing the Ghidra framework to possible malware in those binaries.
    * The python script `acquireExternalExemplars.py` downloads a recent Fedora RISCV-64 disk image, extracting kernel, kernel module,
      system library, and system executable exemplars for use in CI testing or manual investigation.
* Generate a set of smaller Ghidra-importable exemplar binaries tailored to show a particular feature or problem area.  These are provided as
  C or C++ source files with generated compiled binaries saved in `exemplar` directories.
    * The python script `generateInternalExemplars.py` generates many of these small binaries
* Import the internal and external binaries into Ghidra to support manual analysis.
    * The python script `importExemplars.py` imports large and small binaries into a single Ghidra project, applying selected Ghidra java scripts
      to annotate or test the import results.
* Evaluate potential future challenges for Ghidra imports, estimating the time we have until the challenge lands at our feet and the time it may
  take to address those challenges.

To limit the scope this project concentrates on the RISCV-64 hardware platform with selected comparisons to mainstream x86-64 platforms.
The baseline compiler is gcc-13, with an unreleased snapshot gcc-14 compiler used to explore near-future code generation challenges.
