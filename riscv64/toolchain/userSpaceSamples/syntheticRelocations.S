.file   "syntheticRelocations.S"
.option pic
.attribute arch, "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicsr2p0"
.attribute unaligned_access, 0
.attribute stack_align, 16
    .text
    .section        .text.startup.main,"ax",@progbits
    .align  1
    .globl  main
    .type   main, @function
main:
    addi    sp,sp,-16
    sd      ra,8(sp)
    lla     a0,bssString
    sb      zero,8(a0)
    sb      zero,bssString+2049,a5
    call    printf@plt
# use explicit pc-relative relocations to repeat the accesses
1:
    auipc   a0,%pcrel_hi(bssString)
    addi    a0,a0,%pcrel_lo(1b)
1:
    auipc   a0,%pcrel_hi(bssString+2049)
    sb      zero,%pcrel_lo(1b)(a0)
# normal function return 
    ld      ra,8(sp)
    li      a0,0
    addi    sp,sp,16
    jr      ra
    .size   main, .-main
    .globl  bssString
     .section        .bss.bssString,"aw",@nobits
    .align  3
    .type   bssString, @object
    .size   bssString, 4096
bssString:
   .zero   4096
