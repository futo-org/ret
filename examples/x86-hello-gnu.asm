// NOTE: AT&T/GAS support in keystone is incomplete
movl $0x9000000, %eax // UART_DR, write here to print characters
movl $'H', (%eax)
movl $'e', (%eax)
movl $'l', (%eax)
movl $'l', (%eax)
movl $'o', (%eax)
movl $'\n', (%eax)
