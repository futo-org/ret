// https://mariokartwii.com/armv8/ is an excellent resource for learning ARM64 Assembly
adr x1, string
ldr w2, UART_DR
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
string:
.ascii "Hello, World\n"
.byte 0
.align 4
skip:
nop
nop
