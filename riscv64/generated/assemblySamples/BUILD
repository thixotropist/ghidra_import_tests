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
        srcs = [
            "{}.S".format(fname),
            "//riscv64/generated/toolchains:gcc_riscv64_compiler_files",
            "//riscv64/generated/toolchains:gcc_riscv_as",
            "//riscv64/generated/toolchains:gcc_riscv_objdump",
            ],
        outs = [
            "{}.o".format(fname), 
            "{}.list".format(fname),
            "{}.objdump".format(fname),
            ],
        cmd = "$(location //riscv64/generated/toolchains:gcc_riscv_as) --march=rv64gcvq{} $(location {}.S) -a -am -a=$(location {}.list) -o $(location {}.o)".format(ext, fname, fname, fname) +
            " && $(location //riscv64/generated/toolchains:gcc_riscv_objdump) -d $(location {}.o) > $(location {}.objdump)".format(fname, fname)
    )
    # our default arch is rv64gv, which must be extended for everything but the vector extensions.
    for (fname, ext) in [
        ("b-ext", "_zba_zbb_zbc_zbs"),
        ("b-ext-64", "_zba_zbb_zbc_zbs"),
        ("h-ext-64", "_h"),       # hypervisor extensions
        ("svinval", "_svinval"),  # ?? used in sifive kernels near hypervisor extensions
        ("vector", ""),
        ("zbkb-64", "_zbkb"),
        ("zbkc", "_zbkc"),
        ("zbkx", "_zbkx"),
        ("fp-zfh-insns", "_zfh"),
        ("zknd-64", "_zknd"),
        ("zkne-64", "_zkne"),
        ("zknh-64", "_zknh"),
        ("zksed", "_zksed"),
        ("zksh", "_zksh"),
        ("zvbb", "_zvbb"),
        ("zvkng", "_zvkng"),
        ("zvksg", "_zvksg"),
        ("zvbc", "_zvbc"),
        ("unknown", "_zbb_zicbom_zicbop_zicboz"),
        ("semantics", ""),
        ("sifive-insns", "_xsfvcp"),
        ("x-thead-ba", "_xtheadba"),
        ("x-thead-bb", "_xtheadbb"),
        ("x-thead-bs", "_xtheadbs"),
        ("x-thead-cmo", "_xtheadcmo"),
        ("x-thead-condmov", "_xtheadcondmov"),
        ("x-thead-mac", "_xtheadmac"),
        ("x-thead-fmemidx", "_xtheadfmemidx"),
        ("x-thead-memidx", "_xtheadmemidx"),
        ("x-thead-mempair", "_xtheadmempair"),
        ("x-thead-sync", "_xtheadsync"),
    ]
]

filegroup(
    name = "exemplars",
    srcs = [
        ":b-ext.o",
        ":b-ext.list",
        ":b-ext.objdump",
        ":b-ext-64.o",
        ":b-ext-64.list",
        ":b-ext-64.objdump",
        ":h-ext-64.o",
        ":h-ext-64.list",
        ":h-ext-64.objdump",
        ":svinval.o",
        ":svinval.list",
        ":svinval.objdump",
        ":sifive-insns.o",
        ":sifive-insns.list",
        ":sifive-insns.objdump",
        ":vector.o",
        ":vector.list",
        ":vector.objdump",
        ":zbkb-64.o",
        ":zbkb-64.list",
        ":zbkb-64.objdump",
        ":zbkc.o",
        ":zbkc.list",
        ":zbkc.objdump",
        ":zbkx.o",
        ":zbkx.list",
        ":zbkx.objdump",
        ":fp-zfh-insns.o",
        ":fp-zfh-insns.list",
        ":fp-zfh-insns.objdump",
        ":zknd-64.o",
        ":zknd-64.list",
        ":zknd-64.objdump",
        ":zkne-64.o",
        ":zkne-64.list",
        ":zkne-64.objdump",
        ":zknh-64.o",
        ":zknh-64.list",
        ":zknh-64.objdump",
        ":zksed.o",
        ":zksed.list",
        ":zksed.objdump",
        ":zksh.o",
        ":zksh.list",
        ":zksh.objdump",
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

filegroup(
        name = "otherSources",
        srcs = [
            "semantics.o",
            "semantics.list",
            "semantics.objdump"]
)

filegroup(
    name = "theadSources",
    srcs = [
        "x-thead-memidx.o",
        "x-thead-memidx.list",
        "x-thead-memidx.objdump",
        "x-thead-ba.o",
        "x-thead-ba.list",
        "x-thead-ba.objdump",
        "x-thead-bb.o",
        "x-thead-bb.list",
        "x-thead-bb.objdump",
        "x-thead-bs.o",
        "x-thead-bs.list",
        "x-thead-bs.objdump",
        "x-thead-cmo.o",
        "x-thead-cmo.list",
        "x-thead-cmo.objdump",
        "x-thead-condmov.o",
        "x-thead-condmov.list",
        "x-thead-condmov.objdump",
        "x-thead-fmemidx.o",
        "x-thead-fmemidx.list",
        "x-thead-fmemidx.objdump",
        "x-thead-mac.o",
        "x-thead-mac.list",
        "x-thead-mac.objdump",
        "x-thead-mempair.o",
        "x-thead-mempair.list",
        "x-thead-mempair.objdump",
        "x-thead-sync.o",
        "x-thead-sync.list",
        "x-thead-sync.objdump",
    ]
)

#
# unpack this archive with tar xf archive.tar --strip-components=4
# to get past the Bazel build directories
genrule(
    name = "archive",
    srcs = [
        ":exemplars",
        ":otherSources",
        ":theadSources",
    ],
    outs = ["archive.tar"],
    cmd = 
        """
        tar cJhf $(location archive.tar) $(locations :exemplars) $(locations :otherSources) $(locations :theadSources)
        """
)

# Try a 32 bit build of the vector extensions

genrule(
    name = "rvv_32",
    srcs = [
        "vector.S",
    ],
    outs = [
        "vector_32.o",
        "vector_32.list",
        "vector_32.objdump",
    ],
    cmd = "{} --march=rv32gv $(location vector.S) -a -am -a=$(location vector_32.list) -o $(location vector_32.o)".format(GAS) +
            " && {} -d $(location vector_32.o) > $(location vector_32.objdump)".format(OBJDUMP)
)

