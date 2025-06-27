// 'b' is short for 'branch'. This tells the CPU to move execution somewhere else.
b skip
mov r0, #0x123 // this never gets called
// labels are defined with a name and a colon. Labels aren't encoded as instructions, they
// are saved by the assembler as offsets in the code.
skip:
