// Hello world that doesn't use adr
ldr w2, UART_DR
ldr w1, string_addr
top:
	ldrb w0, [x1]
	cmp w0, #0x0
	beq end
	str w0, [x2]
	add x1, x1, #0x1
	b top
end:

b skip
UART_DR: .int 0x9000000
string_addr: .int string
string:
.ascii "Hello, World\n"
.byte 0
.align 4
skip:
