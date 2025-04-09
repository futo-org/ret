b skip
string:
.ascii "Hello, World\n"
.byte 0
.align 4
skip:

adr x1, string
top:
	ldrb w0, [x1]
	cmp w0, #0x0
	beq end
	svc #0x0
	add x1, x1, #0x1
	b top
end:
