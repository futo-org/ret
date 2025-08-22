// LI stands for load immediate.
// This is equivalent to mov in other architectures.
li x1, 0x1

// x0 is a zero register. Writes to it will be ignored.
li x0, 0x2

// The add instruction can add two registers
add x2, x1, x1 // x1 = x0 + x0

// addi adds a register to an immediate value (which is a number rather than register)
addi x2, x1, 0x5 // x1 = x0 + x5
