// LI stands for load immediate.
// This is equivalent to mov in other architectures.
li x0, 0x1

// The add instruction can add two registers
add x1, x0, x0 // x1 = x0 + x0

// addi adds a register to an immediate value (which is a number rather than register)
addi x1, x0, #0x5 // x1 = x0 + x5
