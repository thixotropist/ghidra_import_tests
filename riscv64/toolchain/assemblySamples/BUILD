# $ /home2/vendor/binutils-gdb/gas/as-new --version
# GNU assembler (GNU Binutils) 2.41.50.20230903
# Copyright (C) 2023 Free Software Foundation, Inc.
# This program is free software; you may redistribute it under the terms of
# the GNU General Public License version 3 or later.
# This program has absolutely no warranty.
# This assembler was configured for a target of `riscv64-elf-linux-gnu'.

GAS = "/home2/vendor/binutils-gdb/gas/as-new"
OBJDUMP = "/home2/vendor/binutils-gdb/binutils/objdump"

# RVA23U64 Mandatory Extensions (from the draft document https://github.com/riscv/riscv-profiles/blob/main/rva23-profile.adoc)

# The following mandatory extensions were present in RVA22U64.
#    M Integer multiplication and division.
#    A Atomic instructions.
#    F Single-precision floating-point instructions.
#    D Double-precision floating-point instructions.
#    C Compressed Instructions.
#    Zicsr CSR instructions. These are implied by presence of F.
#    Zicntr Base counters and timers.
#    Zihpm Hardware performance counters.
#    Ziccif Main memory regions with both the cacheability and coherence PMAs must support instruction fetch, and any instruction fetches of naturally aligned power-of-2 sizes up to min(ILEN,XLEN) (i.e., 32 bits for RVA23) are atomic.
#    Ziccrse Main memory regions with both the cacheability and coherence PMAs must support RsrvEventual.
#    Ziccamoa Main memory regions with both the cacheability and coherence PMAs must support AMOArithmetic.
#    Zicclsm Misaligned loads and stores to main memory regions with both the cacheability and coherence PMAs must be supported.
#    Za64rs Reservation sets are contiguous, naturally aligned, and a maximum of 64 bytes.
#    Zihintpause Pause instruction.
#    Zba Address computation.
#    Zbb Basic bit manipulation.
#    Zbs Single-bit instructions.
#    Zic64b Cache blocks must be 64 bytes in size, naturally aligned in the address space.
#    Zicbom Cache-Block Management Operations.
#    Zicbop Cache-Block Prefetch Operations.
#    Zicboz Cache-Block Zero Operations.
#    Zfhmin Half-Precision Floating-point transfer and convert.
#    Zkt Data-independent execution time.
#
# The following mandatory extensions are new in RVA23U64:
#    V Vector Extension.
#
#Note
#	 V was optional in RVA22U64.
#    Zvfhmin Vector FP16 conversion instructions.
#    Zihintntl Non-temporal locality hints.
#    Zicond Conditional Zeroing instructions.
#    Zcb Additional 16b compressed instructions.
#    Zfa Additional scalar FP instructions.
#    Zawrs Wait on reservation set.
#    Zjpm Pointer masking (ignore high bits of addresses)

#RVA23U64 Optional Extensions
#
#RVA23U64 has ten profile options (Zbc, Zfh, Zvfh, Zfbfmin, Zvfbfmin, Zvfbfwma, Zvkng, Zvksg, Zvbb, Zvbc).
#
#The following profile option was also present in RVA22U64:
#    Zfh Scalar Half-Precision Floating-Point (FP16).

#RVA23U64 has nine new profile options (Zbc, Zvfh, Zfbfmin, Zvfbfmin, Zvfbfwma, Zvkng, Zvksg, Zvbb, Zvbc):
#    Zbc Scalar carryless multiply.
#    Zvfh Vector half-precision floating-point (FP16).
#    Zfbfmin Scalar BF16 FP conversions.
#    Zvfbfmin Vector BF16 FP conversions.
#    Zvfbfwma Vector BF16 widening mul-add.
#    Zvkng Vector Crypto NIST Algorithms including GHASH.
#    Zvksg Vector Crypto ShangMi Algorithms including GHASH.
#    Zvbb Vector bitmanip extension.
#    Zvbc Vector carryless multiply.

# extension testfiles are imported from binutils-gdb/gas/testsuite/gas/riscv with a suffix change
# from .s to .S.  That suffix change is only needed if we want Bazel to recognize these files
# as needing a platform-dependent resolved gcc toolchain, which isn't the case here.

# For each extension testfile imported from binutils riscv testsuite,
# run a recent snapshot of the Gnu assembler, then run objdump on the resulting
# .o file so we can compare Ghidra's disassembly with the binutils disassembler
[
    genrule(
        name = fname,
        srcs = ["{}.S".format(fname)],
        outs = [
            "{}.o".format(fname), 
            "{}.list".format(fname),
            "{}.objdump".format(fname),
            ],
        cmd = "{} --march=rv64gv{} $(location {}.S) -a -am -a=$(location {}.list) -o $(location {}.o)".format(GAS, ext, fname, fname, fname) +
            " && {} -d $(location {}.o) > $(location {}.objdump)".format(OBJDUMP, fname, fname)
    )
    # our default arch is rv64gv, which must be extended for everything but the vector extensions.
    for (fname, ext) in [
        ("h-ext-64", "_h"),       # hyvervisor extensions
        ("svinval", "_svinval"),  # ?? used in sifive kernels near hypervisor extensions
        ("vector", ""),
        ("zvbb", "_zvbb"),
        ("zvkng", "_zvkng"),
        ("zvksg", "_zvksg"),
        ("zvbc", "_zvbc"),
        ("unknown", ""),
        ("semantics", "")
    ]
]

filegroup(
    name = "exemplars",
    srcs = [
        ":h-ext-64.o",
        ":h-ext-64.list",
        ":h-ext-64.objdump",
        ":svinval.o",
        ":svinval.list",
        ":svinval.objdump",
        ":vector.o",
        ":vector.list",
        ":vector.objdump",
        ":zvbb.o",
        ":zvbb.list",
        ":zvbb.objdump",
        ":zvkng.o",
        ":zvkng.list",
        ":zvkng.objdump",
        ":zvksg.o",
        ":zvksg.list",
        ":zvksg.objdump",
        ":zvbc.o",
        ":zvbc.list",
        ":zvbc.objdump",
        ":unknown.o",
        ":unknown.list",
        ":unknown.objdump",
    ]
)
[
    filegroup(
        name = "otherSources",
        srcs = [
            fname + ".o",
            fname + ".list",
            fname + ".objdump",
            ],
        )
    for (fname, ext) in [
    ("semantics",""),
    ]
]
#
# unpack this archive with tar xf archive.tar --strip-components=4
# to get past the Bazel build directories
genrule(
    name = "archive",
    srcs = [
        ":exemplars",
    ],
    outs = ["archive.tar"],
    cmd = 
        """
        tar cJhf $(location archive.tar) $(locations :exemplars)
        """
)

