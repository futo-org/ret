const arm64_demo =
`
ldr w2, UART_DR
adr x1, string
top:
	ldrb w0, [x1]
	cmp w0, #0x0
	beq end
	str w0, [x2]
	add x1, x1, #0x1
	b top
end:

b skip
UART_DR: .int 0x9000000
string:
.ascii "Hello, World\\n"
.byte 0
.align 4
skip:
`;
const arm32_demo = `
adr r1, string
ldr r2, UART_DR
top:
	ldrb r0, [r1]
	cmp r0, #0x0
	beq end
	str r0, [r2]
	add r1, r1, #0x1
	b top
end:

b skip
UART_DR: .int 0x9000000
string:
.ascii "Hello, World\\n"
.byte 0
.align 4
skip:
`;
const arm32thumb_demo = `
mov r0, #0x9000000
mov r1, 'X'
str r1, [r0]
`;
const x86_64_demo =
`
mov eax, 0x9000000 // UART_DR
mov dword ptr [eax], 'X'
mov dword ptr [eax], '\\n'
`;
const riscv64_demo =
`
addi x0, x0, 0x12
`;

// Prevent selection while dragging
function pauseEvent(e){
    if (e.stopPropagation) e.stopPropagation();
    if (e.preventDefault) e.preventDefault();
    e.cancelBubble = true;
    e.returnValue = false;
    return false;
}

function createResizeBar(leftPanel, rightPanel, separator) {
	function resizePanel(event) {
		let prevX = event.x;
	
		let lefthPanelWidth = leftPanel.getBoundingClientRect().width;
		let rightPanelWidth = rightPanel.getBoundingClientRect().width;
		function mousemove(e) {
			let distance =  e.x - prevX;
			// Only resize left panel, right panel will flex
			leftPanel.style.flex = "none";
			leftPanel.style.width = `${lefthPanelWidth + distance}px`;
	
			leftPanel.style.userSelect = "none";
			rightPanel.style.userSelect = "none";

			pauseEvent(e);
		}
	
		function mouseup() {
			leftPanel.style.userSelect = "all";
			rightPanel.style.userSelect = "all";
	
			window.removeEventListener('mousemove', mousemove)
			window.removeEventListener('mouseup', mouseup)
		}
	
		window.addEventListener('mousemove', mousemove);
		window.addEventListener('mouseup', mouseup);

		pauseEvent(event);
	}
	separator.addEventListener('mousedown', resizePanel);
}

function setupDropDown(hoverButton, box, hideOnMouseUp = false, onlyShowOnClick = false) {
//box.style.display = "flex";
	if (onlyShowOnClick) {
		hoverButton.addEventListener("click", function() {
			if (box.style.display == "flex") {
				box.style.display = "none";
			} else {
				box.style.display = "flex";
			}
		});
	} else {
		hoverButton.addEventListener("mouseenter", function() {
			box.style.display = "flex";
		});
		hoverButton.addEventListener("mouseleave", function() {
			box.style.display = "none";
		});
	}
	if (hideOnMouseUp) {
		box.addEventListener("mouseup", function() {
			box.style.display = "none";
		});
	}
}

function setupRadio(elementName, initialOptionIndex, callback) {
	var names = document.getElementsByName(elementName);
	for (var i = 0; i < names.length; i++) {
		if (i == initialOptionIndex) {
			names[i].checked = true;
			names[i].classList.add("radio-checked");
		} else {
			names[i].checked = false;
		}
		names[i].index = i;
		names[i].onmousedown = function() {
			if (!this.checked) {
				this.checked = true;
				this.classList.add("radio-checked");
			}
			for (var x = 0; x < names.length; x++) {
				if (x != this.index) {
					names[x].checked = false;
					names[x].classList.remove("radio-checked");
				}
			}
			callback(this.index, this.value, this);
		}
	}
}

const ret = {
	ARCH_ARM64: 0,
	ARCH_ARM32: 1,
	ARCH_X86: 2,
	ARCH_X86_64: 3,
	ARCH_RISCV32: 4,
	ARCH_RISCV64: 5,
	ARCH_WASM: 6,
	ARCH_ARM32_THUMB: 7,

	// Hex parser options
	PARSE_AS_MASK: 0x1f,
	PARSE_AS_U8: 1 << 0,
	PARSE_AS_U16: 1 << 1,
	PARSE_AS_U32: 1 << 2,
	PARSE_AS_U64: 1 << 3,
	PARSE_AS_AUTO: 1 << 4,
	SKIP_1_AT_START: 1 << 5,
	SKIP_2_AT_START: 1 << 6,
	PARSE_AS_BASE_10: 1 << 10,

	// Buffer output options
	OUTPUT_AS_AUTO: 0,
	OUTPUT_AS_U8: 1 << 1,
	OUTPUT_AS_U16: 1 << 2,
	OUTPUT_AS_U32: 1 << 3,
	OUTPUT_AS_U64: 1 << 4,
	OUTPUT_AS_C_ARRAY: 1 << 10,
	OUTPUT_AS_RUST_ARRAY: 1 << 11,

	init: function() {
		this.urlOptions = Object.fromEntries(new URLSearchParams(window.location.search).entries());
		this.currentArch = this.checkArch();
		this.currentParseOption = this.PARSE_AS_AUTO;
		this.currentOutputOption = this.OUTPUT_AS_AUTO;
		this.log("Loading..");
	},
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
			return ret.ARCH_ARM64;
		}
	},
	urlOptions: null,
	currentArch: 0,
	currentBaseOffset: 0,
	currentParseOption: 0,
	currentOutputOption: 0,
	useGodboltOnAssembler: false,

	clearLog: function(str) {
		document.querySelector("#log").value = "";
	},
	log: function(str) {
		document.querySelector("#log").value += str + "\n";
	},
	switchArch: function(arch) {
		if (arch == ret.ARCH_ARM64) {
			window.location.href = "../arm64/";
		} else if (arch == ret.ARCH_X86) {
			window.location.href = "../x86/";
		} else if (arch == ret.ARCH_ARM32) {
			window.location.href = "../arm32/";
		} else if (arch == ret.ARCH_ARM32_THUMB) {
			window.location.href = "../arm32/?thumb";
		} else if (arch == ret.ARCH_RISCV64) {
			window.location.href = "../riscv/";
		} else if (arch == ret.ARCH_RISCV32) {
			window.location.href = "../riscv/?rv32";
		}
	},

	err_buf: null,
	hex_buf: null,
	str_buf: null,
	mem_buf: null,

	main: function() {
		ret.re_init_globals = Module.cwrap('re_init_globals', 'void', []);
		ret.re_is_arch_supported = Module.cwrap('re_is_arch_supported', 'number', []);
		ret.re_is_unicorn_supported = Module.cwrap('re_is_unicorn_supported', 'number', []);
		ret.re_assemble = Module.cwrap('re_assemble', 'number', ['number', 'number', 'number', 'number', 'string', 'number']);
		ret.re_emulator = Module.cwrap('re_emulator', 'number', ['number', 'number', 'number', 'number']);
		ret.re_disassemble = Module.cwrap('re_disassemble', 'number', ['number', 'number', 'number', 'number', 'string']);
		ret.re_get_hex_buffer = Module.cwrap('re_get_hex_buffer', 'number', []);
		ret.re_get_err_buffer = Module.cwrap('re_get_err_buffer', 'number', []);
		ret.re_get_str_buffer = Module.cwrap('re_get_str_buffer', 'number', []);
		ret.re_get_mem_buffer = Module.cwrap('re_get_mem_buffer', 'number', []);
		ret.get_buffer_contents = Module.cwrap('get_buffer_contents', 'string', ['number']);
		ret.parser_to_buf = Module.cwrap('parser_to_buf', 'number', ['string', 'number', 'number', 'number']);

		ret.re_init_globals();
		ret.err_buf = ret.re_get_err_buffer();
		ret.hex_buf = ret.re_get_hex_buffer();
		ret.str_buf = ret.re_get_str_buffer();
		ret.mem_buf = ret.re_get_mem_buffer();

		ret.clearLog();
		ret.log("Ret v4");
		ret.log("Running in WebAssembly with Capstone, keystone, and Unicorn.");
	},

	godbolt: async function(arch, assemblyCode) {
		var compiler = "";
		var arguments = "";
		if (arch == ret.ARCH_ARM64) {
			compiler = "gnuasarm64g1510";
		} else if (arch == ret.ARCH_ARM32) {
			compiler = "gnuasarmhfg54";
		} else if (arch == ret.ARCH_ARM32_THUMB) {
			compiler = "gnuasarmhfg54";
			arguments += "-mthumb ";
		} else if (arch == ret.ARCH_X86_64) {
			compiler = "gnuassnapshot";
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
						intel: false,
						comments: false,
						labels: true,
						directives: true
					}
				}
			})
		});
		return await res.text();
	}
};
ret.init();

setupDropDown(document.querySelector("#hex-dropdown"), document.querySelector("#hex-dropdown-box"));
setupDropDown(document.querySelector("#help-dropdown"), document.querySelector("#help-dropdown-box"));
setupDropDown(document.querySelector("#arch-select"), document.querySelector("#arch-dropdown-box"), false, true);

createResizeBar(
	document.querySelector("#panel1"),
	document.querySelector("#right-column"),
	document.querySelector("#hseparator")
);

document.querySelector("#switch-arm64").onclick = function() {
	ret.switchArch(ret.ARCH_ARM64);
}
document.querySelector("#switch-arm32").onclick = function() {
	ret.switchArch(ret.ARCH_ARM32);
}
document.querySelector("#switch-arm32thumb").onclick = function() {
	ret.switchArch(ret.ARCH_ARM32_THUMB);
}
document.querySelector("#switch-x86").onclick = function() {
	ret.switchArch(ret.ARCH_X86);
}
document.querySelector("#switch-riscv").onclick = function() {
	ret.switchArch(ret.ARCH_RISCV64);
}
document.querySelector("#switch-riscv32").onclick = function() {
	ret.switchArch(ret.ARCH_RISCV32);
}

function updatePageArch() {
	// Change menu color depending on arch
	if (ret.currentArch == ret.ARCH_ARM64) {
		document.querySelector("#arch-select-text").innerText = "Arm64";
		document.querySelector("#menu").style.background = "rgb(23 55 81)";
		document.title = "Ret Arm64";
		document.querySelector(".editor").classList.add("language-armasm");
	} else if (ret.currentArch == ret.ARCH_X86 || ret.currentArch == ret.ARCH_X86_64) {
		document.querySelector("#arch-select-text").innerText = "x86";
		document.querySelector("#menu").style.background = "rgb(97 36 48)";
		document.title = "Ret x86";
		document.querySelector(".editor").classList.add("language-x86asm2");
	} else if (ret.currentArch == ret.ARCH_ARM32) {
		document.querySelector("#arch-select-text").innerText = "Arm32";
		document.querySelector("#menu").style.background = "rgb(19 73 64)";
		document.title = "Ret Arm32";
		document.querySelector(".editor").classList.add("language-armasm");
	} else if (ret.currentArch == ret.ARCH_ARM32_THUMB) {
		document.querySelector("#arch-select-text").innerText = "Arm32 Thumb";
		document.querySelector("#menu").style.background = "rgb(24 91 83)";
		document.title = "Ret Arm32 Thumb";
		document.querySelector(".editor").classList.add("language-armasm");
	} else if (ret.currentArch == ret.ARCH_RISCV64) {
		document.querySelector("#arch-select-text").innerText = "RISC-V";
		document.querySelector("#menu").style.background = "rgb(170 65 18)";
		document.title = "Ret RISC-V";
		document.querySelector(".editor").classList.add("language-armasm");
	} else if (ret.currentArch == ret.ARCH_RISCV32) {
		document.querySelector("#arch-select-text").innerText = "RISC-V 32";
		document.querySelector("#menu").style.background = "rgb(165 99 70)";
		document.title = "Ret RISC-V 32";
		document.querySelector(".editor").classList.add("language-armasm");
	}
}

updatePageArch();
function escape_html(s) {
	return s.replace(/&/g, '&amp;')
	        .replace(/</g, '&lt;')
	        .replace(/>/g, '&gt;');
}

const highlight = editor => {
	delete editor.dataset.highlighted;
	editor.innerHTML = escape_html(editor.textContent);
	hljs.highlightElement(editor);
};

let editor = CodeJar(document.querySelector(".editor"), highlight, {tab: '\t'});

// Set editor text if empty (will not be if window was duplicated)
if (editor.toString() == "") {
	switch (ret.currentArch) {
		case ret.ARCH_ARM64: editor.updateCode(arm64_demo.trim()); break;
		case ret.ARCH_X86_64: editor.updateCode(x86_64_demo.trim()); break;
		case ret.ARCH_ARM32: editor.updateCode(arm32_demo.trim()); break;
		case ret.ARCH_ARM32_THUMB: editor.updateCode(arm32thumb_demo.trim()); break;
		case ret.ARCH_RISCV64: editor.updateCode(riscv64_demo.trim()); break;
	}
}

function finishAssembler(code) {
	var then = Date.now();
	var rc = ret.re_assemble(ret.currentArch, ret.currentBaseOffset, ret.hex_buf, ret.err_buf, code, ret.currentOutputOption);
	var now = Date.now();
	if (rc != 0) {
		ret.log(ret.get_buffer_contents(ret.err_buf));
	} else {
		document.querySelector("#bytes").value = ret.get_buffer_contents(ret.hex_buf);
		ret.log("Assembled in " + String(now - then) + "us");
	}
}

document.querySelector("#assemble").onclick = function() {
	if (ret.hex_buf == null || ret.err_buf == null) throw "NULL";
	ret.clearLog();
	var code = editor.toString();
	if (!code.endsWith("\n")) {
		// make file valid
		code += "\n";
	}
	if (ret.useGodboltOnAssembler) {
		(async function() {
			var x = await ret.godbolt(ret.currentArch, code);
			if (x != null) {
				var split = x.split("\nStandard error:\n");
				if (split.length == 1) {
					ret.log("No errors from Godbolt API.");
					finishAssembler(code);
				} else {
					ret.log("Error message from Godbolt API:");
					ret.log(split[1]);
				}
			} else {
				// Request error
			}
		})();
	} else {
		finishAssembler(code);
	}
}

document.querySelector("#disassemble").onclick = function() {
	if (ret.hex_buf == null || ret.err_buf == null) throw "NULL";	
	ret.clearLog();
	var then = Date.now();
	var rc = ret.re_disassemble(ret.currentArch, ret.currentBaseOffset, ret.str_buf, ret.err_buf, document.querySelector("#bytes").value);
	var now = Date.now();
	if (rc != 0) {
		ret.log(ret.get_buffer_contents(ret.err_buf));
	} else {
		editor.updateCode(ret.get_buffer_contents(ret.str_buf));
		ret.log("Disassembled in " + String(now - then) + "us");
	}
}

document.querySelector("#run").onclick = function() {
	if (ret.mem_buf == null || ret.err_buf == null || ret.str_buf == null) throw "NULL";	
	ret.clearLog();
	if (ret.re_is_unicorn_supported() == 0) {
		ret.log("This target doesn't have Unicorn VM support.");
		return;
	}
	var code = editor.toString();
	var rc = ret.re_assemble(ret.currentArch, ret.currentBaseOffset, ret.mem_buf, ret.err_buf, code, ret.currentOutputOption);
	if (rc != 0) {
		ret.log(ret.get_buffer_contents(ret.err_buf));
	} else {
		rc = ret.re_emulator(ret.currentArch, ret.currentBaseOffset, ret.mem_buf, ret.str_buf);
		ret.log(ret.get_buffer_contents(ret.str_buf));
	}
}

document.querySelector("#hex-dropdown").onclick = function(e) {
	if (!document.querySelector("#hex-dropdown-box").contains(e.target)) {
		if (ret.hex_buf == null) throw "NULL";	
		ret.clearLog();
		var rc = ret.parser_to_buf(document.querySelector("#bytes").value, ret.hex_buf, ret.currentParseOption, ret.currentOutputOption);
		if (rc != 0) {
			ret.log("Failed to parse bytes");
		} else {
			document.querySelector("#bytes").value = ret.get_buffer_contents(ret.hex_buf);
			var output_as = "auto", parse_as = "";
			if (ret.currentParseOption & ret.PARSE_AS_U8) parse_as = "u8";
			if (ret.currentParseOption & ret.PARSE_AS_U16) parse_as = "u16";
			if (ret.currentParseOption & ret.PARSE_AS_U32) parse_as = "u32";
			if (ret.currentParseOption & ret.PARSE_AS_AUTO) parse_as = "auto";
			if (ret.currentParseOption & ret.PARSE_AS_U64) parse_as = "u64";
			if (ret.currentParseOption & ret.PARSE_AS_BASE_10) parse_as = ", base10";

			ret.log("Formatted hex (parse as '" + parse_as + "') (output as '" + output_as + "')");
		}
	}
}

document.querySelector("#base-address").value = "0x" + (ret.currentBaseOffset).toString(16);
document.querySelector("#base-address").onkeyup = function() {
	if (Number(this.value) != NaN) {
		ret.currentBaseOffset = Number(this.value);
	}
}

setupRadio("select_parse_as", 0, function(index, value, e) {
	var option = 0;
	if (index == 0) option = ret.PARSE_AS_AUTO;
	if (index == 1) option = ret.PARSE_AS_U8;
	if (index == 2) option = ret.PARSE_AS_U16;
	if (index == 3) option = ret.PARSE_AS_U32;
	ret.currentParseOption = (ret.currentParseOption & (~ret.PARSE_AS_MASK)) | option;
});


setupRadio("select_output_as", 0, function(index, value, e) {
	var option = 0;
	if (index == 0) option = ret.OUTPUT_AS_AUTO;
	if (index == 1) option = ret.OUTPUT_AS_U8;
	if (index == 2) option = ret.OUTPUT_AS_U32;
	ret.currentOutputOption = (ret.currentOutputOption & (~0x1f)) | option;
});

// Try to get F9 to trigger assembler
document.addEventListener("keydown", keyCapt, false); 
document.addEventListener("keyup", keyCapt, false);
document.addEventListener("keypress", keyCapt, false);
function keyCapt(e) {
	if (typeof window.event != "undefined") {
		e = window.event;	
	}
	if (e.type == "keydown" && (e.keyCode == 120)) {
		document.querySelector("#assemble").click();
	}
}
