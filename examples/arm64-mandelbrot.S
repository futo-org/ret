// This is adapted from the Rosetta Code example:
// https://rosettacode.org/wiki/Mandelbrot_set#AArch64_Assembly

// .req can be used to create an alias for an identifier.
// In this case, we create a bunch of register aliases.
xsize   .req x9
xsize_w .req w9
ysize   .req x10
ysize_w .req w10

min_imag .req s8
max_imag .req s9
min_real .req s10
max_real .req s9

imag .req s11
real .req s12

step_x .req s13
step_y .req s14

zi .req s15
zr .req s16

a .req s17
b .req s18

ftemp_1 .req s19
ftemp_2 .req s20

y .req x19
y_w .req w19
x .req x20
x_w .req w20
n .req x21
limit .req x22

itemp_1 .req x23
itemp_1w .req w23

main:
	mov xsize, #108/2
	mov ysize, #72/2
	mov limit, #32
	fmov min_imag, #-1.0
	fmov max_imag, #1.0
	fmov min_real, #-2.0
//	fmov max_real  #1.0

	fsub  step_x,   max_real, min_real
	scvtf ftemp_1,  xsize_w
	fdiv  step_x,   step_x, ftemp_1
	fsub  step_y,   max_imag, min_imag
	scvtf ftemp_1,  ysize_w
	fdiv  step_y,   step_y, ftemp_1

	mov y, #0
loop_y:
	cmp y, ysize
	b.eq end_loop

	scvtf ftemp_1, y_w
	fmadd imag, step_y, ftemp_1, min_imag

	mov x, #0
loop_x:
	cmp x, xsize
	b.eq end_line

	scvtf ftemp_1, x_w
	fmadd real, step_y, ftemp_1, min_real

	fmov zr, real
	fmov zi, imag

	mov n, #0
loop_iter:
	cmp n, limit
	b.eq draw_point

	fmul a, zr, zr
	fmul b, zi, zi
	fadd ftemp_1, a, b

	fmov ftemp_2, #4.0
	fcmp ftemp_1, ftemp_2
	b.gt draw_point

	fmul  zi, zi, zr
	fmov  ftemp_2, #2.0
	fmadd zi, zi, ftemp_2, imag
	fsub  zr, a, b
	fadd  zr, zr, real

	add n, n, #1
	b loop_iter

draw_point:
	add x, x, #1
	mov x1, 0x9000000
	mov x0, #64
	sub x0, x0, n
	str w0, [x1]
	b loop_x

end_line:
	add y, y, #1
	mov x1, 0x9000000
	mov w0, '\n'
	str w0, [x1]
	b loop_y

end_loop:
