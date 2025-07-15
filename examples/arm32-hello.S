// https://armasm.com/ is an excellent resource for learning ARM Assembly
adr r1, string
ldr r2, UART_DR
top:
	ldrb r0, [r1]
	cmp r0, #0x0
	beq end
	str r0, [r2]
	add r1, r1, #0x1
	b top
end:

b skip
UART_DR: .int 0x9000000
string:
.ascii "Hello, World\n"
.byte 0
.align 2 
skip:
