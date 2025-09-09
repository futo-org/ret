// LI stands for load immediate.
// This is equivalent to mov in other architectures.
li a1, 0x1

// x0 is a zero register. Writes to it will be ignored.
li x0, 0x2

// Read more about the RISC-V ABI: https://en.wikichip.org/wiki/risc-v/registers

// The add instruction can add two registers
add a2, a1, a1 // x1 = x0 + x0

// addi adds a register to an immediate value (which is a number rather than register)
addi a2, a1, 0x5 // x1 = x0 + x5
