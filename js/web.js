const arm64_demo =
`
b skip
string:
.ascii "Hello, World\n"
.byte 0
.align 4
skip:

adr x1, string
top:
	ldrb w0, [x1]
	cmp w0, #0x0
	beq end
	svc #0x0
	add x1, x1, #0x1
	b top
end:
nop;nop;nop // Unicorn bug requires this (?)
`;

const ret = {
	re_log: Module.cwrap('re_log', 'void', ['number', 'string']),
	re_init_globals: Module.cwrap('re_init_globals', 'void', []),
	re_assemble: Module.cwrap('re_assemble', 'number', ['number', 'number', 'number', 'number', 'string']),
	re_get_hex_buffer: Module.cwrap('re_get_hex_buffer', 'number', []),
	re_get_err_buffer: Module.cwrap('re_get_err_buffer', 'number', []),
	re_get_str_buffer: Module.cwrap('re_get_str_buffer', 'number', []),
	get_buffer_contents: Module.cwrap('get_buffer_contents', 'string', ['number']),
	log: function(str) {
		ret.re_log(0, str);
	},

	main: function() {
		ret.re_init_globals();
		let err_buf = ret.re_get_err_buffer();
		let hex_buf = ret.re_get_hex_buffer();

		ret.log("Hello\n");
		let rc = ret.re_assemble(3, 0, hex_buf, err_buf, arm64_demo);
		console.log(rc);
		console.log(ret.get_buffer_contents(hex_buf));
	},
};

Module['onRuntimeInitialized'] = ret.main;
