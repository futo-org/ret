b skip
my_second_func:
	ret
my_func:
	// lr (link register) must be preserved between function calls
	// so the CPU knows where to return to after a nested call
	str lr, [sp, #-0x8]!
	bl my_second_func
	ldr lr, [sp], 0x8
	ret
skip:

bl my_func
