mov eax, 0x9000000 // UART_DR
mov dword ptr [eax], 'X'
mov dword ptr [eax], '\n'
