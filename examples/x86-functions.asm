jmp skip
my_func2:
	ret

my_func:
	call my_func2
	ret
skip:

call my_func
