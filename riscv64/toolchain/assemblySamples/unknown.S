# apparent instructions found in external binaries
#    search binutils source file include/opcode/riscv-opc.h
    .word 0x18000073    # found in vmlinux kvm_riscv_local_hfence_vvma_asid_gva; MATCH_SFENCE_W_INVAL
    .word 0x26b60073    # MATCH_HINVAL_VVMA
    .word 0x18100073    # MATCH_SFENCE_INVAL_IR
    .word 0x26058073
    .word 0x66078073    # MATCH_HINVAL_GVMA

