; Adapted from https://rosettacode.org/wiki/Sierpinski_triangle#X86_Assembly
mov ebp, 0x9000000 ; uart_dr
start: xor     ebx, ebx        ; S1:= 0
	mov     edx, 0x8000      ; S2:= $8000
	mov     cx, 0x16          ; for I:= Size downto 1
tri10: mov     ebx, edx        ; S1:= S2
tri15: test    edx, edx        ; while S2#0
	je      tri20
	mov    al, '*'         ; ChOut
	test   dl, 0x01         ;  if S2&1 then '*' else ' '
	jne    tri18
	mov   al, ' '
tri18: mov [ebp], eax ; write to uart_dr
	shr    edx, 1          ; S2>>1
	jmp    tri15
tri20: mov     al, 0x0D         ; carriage return
	mov [ebp], eax ; write to uart_dr
	mov     al, '\n'
	mov [ebp], eax ; write to uart_dr
	shl     ebx, 1          ; S2:= S2 xor S1<<1
	xor     edx, ebx
	shr     ebx, 2          ; S2:= S2 xor S1>>1
	xor     edx, ebx
	dec    ecx ; dec/cmp/jne can also be `loop tri10`
	cmp ecx, 6
	jne tri10 ; next I
