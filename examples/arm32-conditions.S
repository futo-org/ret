mov r0, #0x10
mov r1, #0x20
cmp r0, r1
blt end // Jump to end if r0 > r1
mov r0, #0x123 // this doesn't get run
end:
// Note: blt stands for 'branch if less than'
// There is also bgt 'brand if greater than', beq, etc
