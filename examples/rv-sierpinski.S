// https://godbolt.org/z/T456vdqoe
main:
        li      a4,((1 << 6) - 1)
        addi a0, a4, 1
        li      a3,0x9000000
        li      a1,32
        li      a6,10
        li      a7,-1
.L2:
        li      a5,0
        j       .L8
.L3:
        sw      a1,0(a3)
        addi    a5,a5,1
.L8:
        bne     a5,a4,.L3
        li      a2,0
        sub     t1,a0,a4
.L4:
        bne     a2,t1,.L6
        addi    a4,a4,-1
        sw      a6,0(a3)
        bne     a4,a7,.L2
        li      a0,0
        j end
.L6:
        and     a5,a2,a4
        seqz    a5,a5
        neg     a5,a5
        andi    a5,a5,10
        addi    a5,a5,32
        sw      a5,0(a3)
        sw      a1,0(a3)
        addi    a2,a2,1
        j       .L4
end:
