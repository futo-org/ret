la a0, string
li a2, 0x9000000

top:
lbu a1, 0(a0)
sw a1, 0(a2)
addi a0, a0, 1
bne a1, zero, top

j skip
string: .string "Hello World"
.align 1
skip:
