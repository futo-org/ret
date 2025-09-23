# PowerPC support is not fully finished yet
# Unicorn doesn't support ppc64, so this is in 32 bit mode by default.
lis r3, 0x900 # UART_DR 0x9000000
addi r2, r0, 'X'
stw r2, 0x0 (r3)
addi r2, r0, '\n'
stw r2, 0x0 (r3)
