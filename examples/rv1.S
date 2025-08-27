// This isn't working (depends on linker relocation being done)
x:
auipc a0, %pcrel_hi(asd)
addi a0, a0, %pcrel_lo(x)
asd:
