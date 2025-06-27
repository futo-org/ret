// Note: the emulator already has the stack pointer setup.
mov r0, #0x123
push {r0} // Pushes 0x123 onto the stack. the stack pointer (sp) gets decremented by 4.
mov r0, #0x0
pop {r0} // Pops the 0x123 back into r0, and sp gets incremented by 4.

// This can also be written as:
stmdb sp!, {r0} // stmdb stands for Store Multiple, Decrement Before
mov r0, #0x0
ldmia sp!, {r0} // ldmia stands for Load multiple, increment after
