// This isn't working (depends on linker relocation being done)
x:
auipc a0, %pcrel_hi(asd)
addi a0, a0, %pcrel_lo(x)
asd:

// This works:
// auipc a0, %pcrel_hi(target)
// addi a0, a0, %pcrel_lo(target) + 4
// target:

// Doesn't work
// lui a0, %hi(x)
// addi a0, a0, %lo(x)
// x:
