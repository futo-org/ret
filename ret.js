const ret = {
	// Default architecture (root-level) will be x86_64
	DEFAULT_ARCH: 3,

	// Architectures and variants
	ARCH_ARM64: 0,
	ARCH_ARM32: 1,
	ARCH_X86: 2,
	ARCH_X86_64: 3,
	ARCH_RISCV32: 4,
	ARCH_RISCV64: 5,
	ARCH_WASM: 6,
	ARCH_ARM32_THUMB: 7,

	// Base Hex parser options
	PARSE_AS_U8: 1 << 0,
	PARSE_AS_U16: 1 << 1,
	PARSE_AS_U32: 1 << 2,
	PARSE_AS_U64: 1 << 3,
	PARSE_AS_AUTO: 1 << 4,
	SKIP_1_AT_START: 1 << 5,
	SKIP_2_AT_START: 1 << 6,
	// Additional options
	PARSE_AS_BASE_10: 1 << 10,
	PARSE_AS_BIG_ENDIAN: 1 << 11,
	PARSE_C_COMMENTS: 1 << 12,

	// Hex buffer output options
	OUTPUT_AS_AUTO: 0,
	OUTPUT_AS_U8: 1 << 1,
	OUTPUT_AS_U16: 1 << 2,
	OUTPUT_AS_U32: 1 << 3,
	OUTPUT_AS_U64: 1 << 4,
	OUTPUT_AS_U32_BINARY: 1 << 5,
	OUTPUT_AS_U8_BINARY: 1 << 6,
	// Additional hex buffer output options (TODO: C Array isn't treated as one)
	OUTPUT_AS_C_ARRAY: 1 << 10,
	OUTPUT_AS_RUST_ARRAY: 1 << 11,
	OUTPUT_AS_BIG_ENDIAN: 1 << 12,
	OUTPUT_SPLIT_BY_FOUR: 1 << 13,
	OUTPUT_SPLIT_BY_INSTRUCTION: 1 << 14,
	OUTPUT_ASSEMBLY_ANNOTATIONS: 1 << 15,

	// Assembly options
	SYNTAX_INTEL: 0,
	SYNTAX_ATT: 1 << 1,
	SYNTAX_NASM: 1 << 2,
	SYNTAX_MASM: 1 << 3,
	SYNTAX_GAS: 1 << 4,
	AGGRESSIVE_DISASM: 1 << 10,

	// has object with initial URL options
	urlOptions: null,

	currentArch: undefined,
	currentSyntax: undefined,
	aggressiveDisasm: false,
	useGodboltOnAssembler: false,
	currentBaseOffset: 0,
	baseParseOption: 0,
	baseOutputOption: 0,
	// Parse options
	parseAsBigEndian: false,
	parseAsBaseTen: false,
	parseCComments: false,
	// Assembly options
	splitBytesByInstruction: false,
	splitBytesByFour: true,

	// Initialize this object from URL options or defaults
	init: function() {
		ret.urlOptions = Object.fromEntries(new URLSearchParams(window.location.search).entries());
		ret.currentArch = ret.checkArch();
		ret.baseParseOption = ret.PARSE_AS_AUTO;
		ret.baseOutputOption = ret.OUTPUT_AS_AUTO;
		ret.currentSyntax = ret.SYNTAX_INTEL;
		if (ret.urlOptions.hasOwnProperty("useGodboltOnAssembler")) {
			ret.useGodboltOnAssembler = true;
		}
		if (ret.urlOptions.hasOwnProperty("baseParseOption")) {
			ret.baseParseOption = Number(ret.urlOptions.baseParseOption);
		}
		if (ret.urlOptions.hasOwnProperty("baseOutputOption")) {
			ret.baseOutputOption = Number(ret.urlOptions.baseOutputOption);
		}
		if (ret.urlOptions.hasOwnProperty("currentSyntax")) {
			ret.currentSyntax = Number(ret.urlOptions.currentSyntax);
		}
		if (ret.urlOptions.hasOwnProperty("parseCComments")) ret.parseCComments = true;
		if (ret.urlOptions.hasOwnProperty("aggressiveDisasm")) ret.aggressiveDisasm = true;
		if (ret.urlOptions.hasOwnProperty("splitBytesByInstruction")) {
			ret.splitBytesByInstruction = (ret.urlOptions.splitBytesByInstruction == "true");
		} else {
			// Don't split bytes by instruction on arm32 or arm64.
			switch (ret.currentArch) {
			case ret.ARCH_X86:
			case ret.ARCH_X86_64:
			case ret.ARCH_RISCV64:
			case ret.ARCH_RISCV32:
			case ret.ARCH_ARM32_THUMB:
				ret.splitBytesByInstruction = true;
				break;
			default:
				ret.splitBytesByInstruction = false;
				break;
			}
		}
		if (ret.urlOptions.hasOwnProperty("splitBytesByFour")) ret.splitBytesByFour = (ret.urlOptions.splitBytesByFour == "true");
		ret.log("Loading...");
	},
	encodeURL: function(allOptions) {
		var opt = Object.assign({}, ret.urlOptions);
		opt.code = encodeURIComponent(editor.toString());
		if (allOptions) {
			opt.baseParseOption = String(ret.baseParseOption);
			opt.baseOutputOption = String(ret.baseOutputOption);
			if (ret.useGodboltOnAssembler) opt.useGodboltOnAssembler = "true";
			if (ret.parseCComments) opt.parseCComments = "true";
			if (ret.aggressiveDisasm) opt.aggressiveDisasm = "true";
			if (ret.splitBytesByInstruction) opt.splitBytesByInstruction = "true";
			if (ret.splitBytesByFour) opt.splitBytesByFour = "true";
			opt.currentSyntax = String(ret.currentSyntax);
		}
		return window.location.origin + window.location.pathname + "?" + new URLSearchParams(opt).toString();
	},
	// TODO: Make this function less dumb
	checkArch: function() {
		if (window.location.pathname.includes("arm64")) {
			return ret.ARCH_ARM64;
		} else if (window.location.pathname.includes("arm") || window.location.pathname.includes("arm32")) {
			if (ret.urlOptions.hasOwnProperty("thumb")) {
				return ret.ARCH_ARM32_THUMB;
			} else {
				return ret.ARCH_ARM32;
			}
		} else if (window.location.pathname.includes("riscv")) {
			if (ret.urlOptions.hasOwnProperty("rv32")) {
				return ret.ARCH_RISCV32;
			} else {
				return ret.ARCH_RISCV64;
			}
			return ret.ARCH_RISCV64;
		} else if (window.location.pathname.includes("x86")) {
			return ret.ARCH_X86_64;
		} else {
			return ret.DEFAULT_ARCH;
		}
	},

	clearLog: function(str) {
		document.querySelector("#log").value = "";
	},
	log: function(str) {
		document.querySelector("#log").value += str + "\n";
	},
	switchArch: function(arch) {
		if (arch == ret.DEFAULT_ARCH) {
			if (ret.currentArch == arch) {
				window.location.href = "./";
			} else {
				window.location.href = "../";
			}
			return;
		}
		var prefix = "../";
		if (ret.currentArch == ret.DEFAULT_ARCH) {
			prefix = "";
		}
		if (arch == ret.ARCH_ARM64) {
			window.location.href = prefix + "arm64/";
		} else if (arch == ret.ARCH_X86) {
			window.location.href = prefix + "x86/";
		} else if (arch == ret.ARCH_ARM32) {
			window.location.href = prefix + "arm32/";
		} else if (arch == ret.ARCH_ARM32_THUMB) {
			window.location.href = prefix + "arm32/?thumb";
		} else if (arch == ret.ARCH_RISCV64) {
			window.location.href = prefix + "riscv/";
		} else if (arch == ret.ARCH_RISCV32) {
			window.location.href = prefix + "riscv/?rv32";
		}
	},

	err_buf: null,
	hex_buf: null,
	str_buf: null,
	mem_buf: null,
	hex_mem_mirror_buf: null,

	main: function() {
		ret.re_init_globals = Module.cwrap('re_init_globals', 'void', []);
		ret.re_is_arch_supported = Module.cwrap('re_is_arch_supported', 'number', []);
		ret.re_is_unicorn_supported = Module.cwrap('re_is_unicorn_supported', 'number', []);
		ret.re_assemble = Module.cwrap('re_assemble', 'number', ['number', 'number', 'number', 'number', 'number', 'string', 'number']);
		ret.re_emulator = Module.cwrap('re_emulator', 'number', ['number', 'number', 'number', 'number']);
		ret.re_disassemble = Module.cwrap('re_disassemble', 'number', ['number', 'number', 'number', 'number', 'number', 'string', 'number', 'number']);
		ret.re_get_hex_buffer = Module.cwrap('re_get_hex_buffer', 'number', []);
		ret.re_get_err_buffer = Module.cwrap('re_get_err_buffer', 'number', []);
		ret.re_get_str_buffer = Module.cwrap('re_get_str_buffer', 'number', []);
		ret.re_get_mem_buffer = Module.cwrap('re_get_mem_buffer', 'number', []);
		ret.re_get_hex_mem_mirror_buffer = Module.cwrap('re_get_hex_mem_mirror_buffer', 'number', []);
		ret.get_buffer_contents = Module.cwrap('buffer_get_contents', 'string', ['number']);
		ret.get_buffer_contents_raw = Module.cwrap('buffer_get_contents', 'number', ['number']);
		ret.get_buffer_data_length = Module.cwrap('buffer_get_data_length', 'number', ['number']);
		ret.parser_to_buf = Module.cwrap('parser_to_buf', 'number', ['string', 'number', 'number', 'number']);
		ret.buffer_to_buffer = Module.cwrap('buffer_to_buffer', 'void', ['number', 'number', 'number']);

		ret.re_init_globals();
		ret.err_buf = ret.re_get_err_buffer();
		ret.hex_buf = ret.re_get_hex_buffer();
		ret.str_buf = ret.re_get_str_buffer();
		ret.mem_buf = ret.re_get_mem_buffer();
		ret.hex_mem_mirror_buf = ret.re_get_hex_mem_mirror_buffer();

		ret.clearLog();
		ret.log("Ret v4 - Reverse-Engineering Tool");
		ret.log("Click the top left button to switch architecture.");
		ret.log("Click 'Examples' to get started.");

		if (ret.re_is_arch_supported(ret.currentArch) == 0) {
			ret.log("ERROR: This architecture was not compiled into the wasm binary.");
		}
	},
	// Try and use the godbolt API for their assembler.
	// We get back assembly (not bytes) but their error checking is useful.
	godbolt: async function(arch, assemblyCode) {
		var compiler = "";
		var arguments = "";
		var useIntel = false;
		if (arch == ret.ARCH_ARM64) {
			compiler = "gnuasarm64g1510";
		} else if (arch == ret.ARCH_ARM32) {
			compiler = "gnuasarmhfg54";
		} else if (arch == ret.ARCH_ARM32_THUMB) {
			compiler = "gnuasarmhfg54";
			arguments += "-mthumb ";
		} else if (arch == ret.ARCH_X86_64 || arch == ret.ARCH_X86) {
			compiler = "gnuassnapshot";
			if (ret.currentSyntax == ret.SYNTAX_INTEL) {
				useIntel = true;
				assemblyCode = ".intel_syntax noprefix\n" + assemblyCode;
			} else if (ret.currentSyntax == ret.SYNTAX_NASM) {
				compiler = "nasm21601";
			}
		} else if (arch == ret.ARCH_RISCV64) {
			compiler = "gnuasriscv64g1510";
		} else if (arch == ret.ARCH_RISCV32) {
			compiler = "gnuasriscv32g1510";
		} else {
			throw "Error";
		}
		var res = await fetch('https://godbolt.org/api/compiler/' + compiler + '/compile', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify({
				source: assemblyCode,
				options: {
					userArguments: arguments,
					filters: {
						intel: useIntel,
						comments: false,
						labels: true,
						directives: true
					}
				}
			})
		});
		return await res.text();
	},
	getExamples: function() {
		var selected = [];
		for (var i = 0; i < examples.length; i++) {
			const isArm = ret.currentArch == ret.ARCH_ARM32 || ret.currentArch == ret.ARCH_ARM32_THUMB;
			const isX86 = ret.currentArch == ret.ARCH_X86 || ret.currentArch == ret.ARCH_X86_64;
			if (examples[i].arch == "arm32" && isArm) {
				selected.push(examples[i]);
			} else if (examples[i].arch == "x86gnu" && isX86 && ret.currentSyntax == ret.SYNTAX_GAS) {
				selected.push(examples[i]);
			} else if (examples[i].arch == "x86nasm" && isX86 && ret.currentSyntax == ret.SYNTAX_NASM) {
				selected.push(examples[i]);
			} else if (examples[i].arch == "x86intel" && isX86 && ret.currentSyntax == ret.SYNTAX_INTEL) {
				selected.push(examples[i]);
			} else if (examples[i].arch == "arm64" && ret.currentArch == ret.ARCH_ARM64) {
				selected.push(examples[i]);
			} else if ((examples[i].arch == "rv32" || examples[i].arch == "rv") && ret.currentArch == ret.ARCH_RISCV32) {
				selected.push(examples[i]);
			} else if ((examples[i].arch == "rv64" || examples[i].arch == "rv") && ret.currentArch == ret.ARCH_RISCV64) {
				selected.push(examples[i]);
			}
		}
		return selected;
	},
	getExample: function(name) {
		var selected = ret.getExamples();
		for (var i = 0; i < selected.length; i++) {
			if (selected[i].name == name) {
				return selected[i].data;
			}
		}
		return "";
	},

	downloadFile: function(blob) {
		var a = document.createElement("a");
		document.body.appendChild(a);
		a.download = "binary.dat";
		a.href = window.URL.createObjectURL(new Blob([blob], {
			type: "application/octet-stream"
		}));
		a.click();
		document.body.removeChild(a);
	},

	getParseOption: function() {
		var v = ret.baseParseOption;
		if (ret.parseCComments) v |= ret.PARSE_C_COMMENTS;
		return v;
	},
	getOptionOption: function() {
		var v = ret.baseOutputOption;
		if (ret.splitBytesByInstruction && (ret.baseOutputOption != ret.OUTPUT_AS_U32 || ret.baseOutputOption == ret.OUTPUT_AS_U16))
			v |= ret.OUTPUT_SPLIT_BY_INSTRUCTION;
		if (ret.splitBytesByFour && !ret.splitBytesByInstruction)
			v |= ret.OUTPUT_SPLIT_BY_FOUR;
		return v;
	},

	assemble: function(code, outBuf, errBuf) {
		var then = Date.now();
		var rc = ret.re_assemble(ret.currentArch, ret.currentBaseOffset, ret.currentSyntax, outBuf, errBuf, code, ret.getOptionOption());
		var now = Date.now();
		return [rc, now - then];
	},
};
ret.init();
