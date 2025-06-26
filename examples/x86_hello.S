mov eax, 0x9000000 ; UART_DR
mov dword [eax], 'H'
mov dword [eax], 'e'
mov dword [eax], 'l'
mov dword [eax], 'l'
mov dword [eax], 'o'
mov dword [eax], '\n'
