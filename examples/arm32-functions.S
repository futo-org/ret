mov r0, #0x5
mov r1, #0x5
// bl is short for 'branch link'. It saves the current position in lr (the link register)
// and jumps to a label.
bl multiply

b skip
multiply:
	mul r0, r0, r1
	bx lr
skip:
