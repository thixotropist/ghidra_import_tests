# apparent instructions found in external binaries
#    search binutils source file include/opcode/riscv-opc.h
#    or search linux kernel source arch/riscv/include/asm/insn-def.h

    .insn 0x18000073    # found in vmlinux kvm_riscv_local_hfence_vvma_asid_gva; MATCH_SFENCE_W_INVAL
    .insn 0x26b60073    # MATCH_HINVAL_VVMA
    .insn 0x18100073    # MATCH_SFENCE_INVAL_IR
    .insn 0x26058073
    .insn 0x66078073    # MATCH_HINVAL_GVMA
    .insn 0x2872de13    # orc.b
    .insn 0x0015200f    # cbo.clean
    .insn 0x0005200f    # cbo.inval
    .insn 0x0025200f    # cbo.flush
    .insn 0x66a78073
    .insn 0x26058073
