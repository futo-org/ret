mov ebx, 0x9000000 /* UART_DR */

mov esi, string
top:
	lodsb /* Load byte from [ebx] into al, increment ebx by 1 */
	test al, al
	jz end /* jump if zero */
	mov [ebx], al /* Store al into UART_DR */
	jmp top
end:

jmp skip
string: .string "Hello, World\n"
skip:
