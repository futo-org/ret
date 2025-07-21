// ARM has a standardized macro system/preprocessor (that can be used alongside the C preprocessor)

.macro mov32, reg, val
movw \reg, #:lower16:\val
movt \reg, #:upper16:\val
.endm

mov32 r0, 0x12345678
