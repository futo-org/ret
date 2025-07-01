// x0-x28: General-purpose registers
// x29/fp: Frame pointer
// x30/lr: Link register
// All 'x' registers are 64 bit.
mov x0, #0xffffffffffffffff
// The lower (least significant) 32 bits of each 64 bit register can be
// accessed through a 'w' register:
mov w0, #0x123

// Note that fp and lr are just aliases. The following are identical:
mov lr, #0x0
mov x30, #0x0
mov fp, #0x0
mov x29, #0x0
