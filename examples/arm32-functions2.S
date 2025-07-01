bl myfunc

b skip:

myfunc:
	push {lr} // pushes LR onto the stack
	mov r0, #0x123
	pop {pc} // Pops the LR that was on the stack to PC - making the CPU jump back to the original LR

skip:
