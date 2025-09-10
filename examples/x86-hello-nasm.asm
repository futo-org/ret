; NOTE: NASM support in keystone is incomplete 
mov ebx, 0x9000000 ; UART_DR, write here to print characters

mov esi, string
top:
	lodsb ; Load byte from [esi] into al, increment esi by 1
	test al, al
	jz end ; jump if zero
	mov [ebx], al ; Store al into UART_DR
	jmp top
end:

jmp skip
string: db "Hello, World\n\0"
skip:
