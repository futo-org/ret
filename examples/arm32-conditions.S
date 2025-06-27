mov r0, #0x10
mov r1, #0x20
// This copies r0 and r1 into some internal registers. These internal registers are used
// by conditional branch instructions.
cmp r0, r1
// Jump to end if r0 < r1
// blt is a conditional branch instructions. There are others, like bgt (branch greater than), beq, etc
blt end
mov r0, #0x123 // Since 0x10 < 0x20, this instruction doesn't get run.
end:
