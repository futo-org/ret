// Call the supervisor with command 0x84000008 (SYSTEM_OFF)
mov x0, 0x84000000
add x0, x0, #0x8
svc #0x0
