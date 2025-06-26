function addExample(arch, name, code) {
	
}

addExample("rv64", "Registers",
`
// The following instructions are equivalent
addi x0, x0, 0x1
li x0, 0x1
// x1 will be 0x2
add x1, x0, x0
`
);

addExample("arm32", "Jumps",
`
b skip
mov r0, #0x123 // this never gets called
skip:
`
);
addExample("arm32", "Conditions",
`
mov r0, #0x10
mov r1, #0x20
cmp r0, r1
blt end // Jump to end if r0 > r1
mov r0, #0x123 // this doesn't get run
end:
// Note: blt stands for 'branch if less than'
// There is also bgt 'brand if greater than', beq, etc
`
);
addExample("arm32", "Stack",
`
// Note: the emulator already has the stack pointer setup.
mov r0, #0x123
push {r0}
mov r0, #0x0
pop {r0}
`
);
addExample("arm32", "Functions",
`
// 0x5 * 0x5 = 0x19
mov r0, #0x5
mov r1, #0x5
bl multiply

b skip
multiply:
	mul r0, r0, r1
	bx lr
skip:
`
);

const arm64_demo =
`
ldr w2, UART_DR
adr x1, string
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
.ascii "Hello, World\\n"
.byte 0
.align 4
skip:
`;
const arm64_demo_pic =
`
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
.ascii "Hello, World\\n"
.byte 0
.align 4
skip:
`;
const arm32_demo = `
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
.ascii "Hello, World\\n"
.byte 0
.align 4
skip:
`;
const arm32_add_numbers = `
// Add two numbers
mov r0, #0x50
mov r1, #0xb0
add r2, r0, r1 // r2 = r0 + r1
`;
const x86_64_demo =
`
mov eax, 0x9000000 ; UART_DR
mov dword [eax], 'X'
mov dword [eax], '\\n'
`;
const x86_demo_gnu =
`
mov eax, 0x9000000 // UART_DR
mov dword ptr [eax], 'X'
mov dword ptr [eax], '\\n'
`;
const riscv64_demo =
`
addi x0, x0, 0x12
`;
