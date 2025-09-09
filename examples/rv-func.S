j skip
nested:
	jr ra

myfunc:
	addi sp, sp, -8
	sd ra, 0(sp) // ra = return address
	call nested
	li a0, 0x123
	ld ra, 0(sp)
	addi sp, sp, 8
	jr ra
skip:

call myfunc
