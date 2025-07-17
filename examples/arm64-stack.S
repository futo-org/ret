mov x0, #0x123

// The ! flag at the end of this instruction will update the register we are writing to.
// In this case x0 is written to sp - 8, and 8 is subtracted from sp.
str x0, [sp, #-0x8]!
// So that is equivalent to:
str x0, [sp, #-0x8]
sub sp, sp, 0x8

mov x0, #0x0

// This loads the value back into x0, and increments sp by 8
ldr x0, [sp], 0x8

// Store and Load multiple
stp x0, x1, [sp, #-0x10]!
ldp x0, x1, [sp], #0x10
