// Get current exception level
// https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers/CurrentEL--Current-Exception-Level

mrs x0, CurrentEL
lsr x0, x0, #0x2
// We are in EL1!
