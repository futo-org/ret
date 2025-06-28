// Note: RISC-V doesn't work in the web-based emulator yet.
// RISC-V Resources: "https://msyksphinz-self.github.io/riscv-isadoc" 

li x0, 0x9000000
li x1, 'X'
sw x1, 0(x0) // Store word x1 into address at x0 at offset 0
li x1, '\n'
sw x1, 0(x0)
