// Arm64 has 32 128bit floating point/simd registers.

adr x0, dat

// Each register has a:
ldr q0, [x0] // 128bit variant
ldr d0, [x0] // 64bit variant
ldr s0, [x0] // 32bit variant
ldr h0, [x0] // 16bit variant
ldr b0, [x0] // 8bit variant

// You can't use mov on these registers. You can use fmov, but only for 32bit/64bit.
fmov d0, x0
fmov s0, w0

b skip
dat:
.int 0x0
.int 0x0
.int 0x0
.int 0x0
skip:
