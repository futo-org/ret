mov eax, 0x9000000 // UART_DR
mov dword ptr [eax], 'H'
mov dword ptr [eax], 'e'
mov dword ptr [eax], 'l'
mov dword ptr [eax], 'l'
mov dword ptr [eax], 'o'
mov dword ptr [eax], '\n'
