// 0x5 * 0x5 = 0x19
mov r0, #0x5
mov r1, #0x5
bl multiply

b skip
multiply:
	mul r0, r0, r1
	bx lr
skip:
