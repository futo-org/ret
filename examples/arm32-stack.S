// Note: the emulator already has the stack pointer setup.
mov r0, #0x123
push {r0}
mov r0, #0x0
pop {r0}
