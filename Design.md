# Integration Test Design

This project is more of a proof-of-concept project than a design concept.  It seeks to demonstrate what's possible at
a modest cost in complexity.  It doesn't pretend to show a strong design for a ghidra import integration package.  In
fact, it is more likely to show how much a thorough overall design review is needed, followed by a total refactoring and rewrite.

Test organization is a big design question.  Should tests (and test directory trees) be organized to line up with Ghidra's source directory tree?
With target platform? Or with the origin of the binary test exemplar?  The current design organizes directories by target platform,
then by the origin or class of the exemplars.  Riscv-64 is currently the only target platform.  Origin/class currently includes a set of imported
exemplars (Linux kernel, Linux kernel module, system library, system executable) and a set of locally compiled C or C++ or assembly exemplars.

The exemplars all have a preparation phase.  Imported exemplars need an expensive fetch of an external disk image, followed by a breakout of each exemplar
from that image.  Locally compiled exemplars require one or more imported toolchains, which generally need to be checked thoroughly before the exemplars are checked.
Imported exemplars are prepared with a top-level Makefile, then tested by importing into Ghidra's `analyzeHeadless` tool in the top level integrationTest.py. 
Locally compiled exemplars are generated within the setup phase of local integrationTest.py files, for example `riscv/toolchain/integrationTest.py`,
with no connection to the top level Makefile.

However the exemplars are obtained, they are cached locally then imported into Ghidra with `analyzeHeadless`.  Some imports require a Java `preScript`, for instance
kernel images that don't include Elf load addresses and symbol locations.
All exemplars should eventually use a Java `postScript` file to verify the correctness of the import. Those `postScript` files can apply a set of assertion tests
within the GhidraScript context, generating test results as json files.  Those json files can then be imported into the Python `ingrationTest.py` framework for regression reporting.

## Definitions and conventions

### Definitions

exemplar
: An example of a binary file one might expect Ghidra to accept as input.  This might be an ELF executable, an ELF object file or library of object files, a kernel load module,
or a kernel vmlinux image.  Ideally it should be relatively small and easy to screen for hidden malware.  Not all features demonstrated by the exemplar need be supported
by the current Ghidra release.

platform
: The technology base one or more exemplars are used on.  A kernel exemplar expects to be run on top of a bootloader platform.  A Linux application exemplar may consider
the Linux kernel plus system libraries as its platform.  System libraries like libc.so can then be both exemplars and platform elements.

crosscompiler
: A compiler capable of generating code for a processor other than the one it is running on.  An x86_64 gcc-12 compiler configured to generate riscv-64 object files would be a crosscompiler.
Crosscompilers run on either the local host platform or on a Continuous Integration test server platform, generating object files (*.o)

linker
: A tool that takes one or more object files and resolves those runtime linkages internal to those object files.  Usually `ld` on a Linux system.  Often generates an ELF file
or a kernel image.

loader
: A tool - often integrated with the kernel - that loads an Elf file into RAM.  The loader finalizes runtime linkages with external objects.  The loader will often rewrite
code (aka `relaxation`) to optimize memory references and so performance.

sysroot
: The system root directories provide the interface between platform (kernel and system libraries) and user code.
This can be as simple as `/usr/include` or as complicated as a `sysroot/lib/ldscripts` holding
over 250 ld scripts detailing how a linker should generate code the kernel loader can fully process.
Crosscompiler toolchains often need to import a sysroot to build for a given kernel.  This can make for a circular dependency.

toolchain
: A toolchain is an assembly of crosscompiler, linker, loader, and sysroot, plus a default set of options and switches for each component.  Different toolchains might share a gcc-12
crosscompiler but be configured for different platforms - building a kernel image, building `libc.so``, or building an executable application.

workspace
: An environment that provides mappings between platforms and toolchains.  If you want to build an executable for a given platform, just name that platform on the command line
and the build tool will select a compatible toolchain and a *default* set of options.  You can still override those options.

hermetic
: Build artifacts are not affected by any local host files other than those imported with the toolchain.  A hermetic build on a Fedora platform will generate exactly the same
binary output as if built on an Ubuntu platform.  This allows remote build servers to cache build artifacts and CI/CD servers to use exactly the same build environment as a diverse
devlopment team.

### Conventions

This project started with a hypothetical - would a RISCV-64 CPU platform be attractive for network apps?  Perhaps something that helped implement a Zero Trust Networking enterprise model?
If so, would Ghidra be useful for debugging the many innovative features offered by RISCV-64 processors?

For concreteness, we're concentrating on hardware platforms something like [RISCV SiFive Horse Creek Development Board](https://liliputing.com/sifive-hifive-pro-p550-dev-board-coming-this-summer-with-intel-horse-creek-risc-v-chip/) with a Linux 6.x kernel and a sysroot similar to that of Ubuntu or Fedora.
RISCV-64 designs allow for many cores at relatively low power.  That's good for network throughput, but puts a lot of stress on memory bandwidth and cross-cpu cache consistency.
RISCV processor designs address this with *many* different atomic and memory barrier instructions, plus a new set of vector instructions.  That's a lot of ways to fail.