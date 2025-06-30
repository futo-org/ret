// Prevent selection while dragging
function pauseEvent(e) {
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
	PARSE_AS_BIG_ENDIAN: 1 << 11,
	PARSE_C_COMMENTS: 1 << 12,

	// Buffer output options
	OUTPUT_AS_AUTO: 0,
	OUTPUT_AS_U8: 1 << 1,
	OUTPUT_AS_U16: 1 << 2,
	OUTPUT_AS_U32: 1 << 3,
	OUTPUT_AS_U64: 1 << 4,
	OUTPUT_AS_C_ARRAY: 1 << 10,
	OUTPUT_AS_RUST_ARRAY: 1 << 11,

	SYNTAX_INTEL: 0,
	SYNTAX_ATT: 1,
	SYNTAX_NASM: 2,
	SYNTAX_MASM: 3,
	SYNTAX_GAS: 4,

	init: function() {
		this.urlOptions = Object.fromEntries(new URLSearchParams(window.location.search).entries());
		this.currentArch = this.checkArch();
		this.currentParseOption = this.PARSE_AS_AUTO;
		this.currentOutputOption = this.OUTPUT_AS_AUTO;
		this.currentSyntax = this.SYNTAX_INTEL;
		if (ret.urlOptions.hasOwnProperty("useGodboltOnAssembler")) {
			this.useGodboltOnAssembler = true;
		}
		if (ret.urlOptions.hasOwnProperty("currentParseOption")) {
			this.currentParseOption = Number(ret.urlOptions.currentParseOption);
		}
		if (ret.urlOptions.hasOwnProperty("currentOutputOption")) {
			this.currentOutputOption = Number(ret.urlOptions.currentOutputOption);
		}
		if (ret.urlOptions.hasOwnProperty("currentSyntax")) {
			this.currentSyntax = Number(ret.urlOptions.currentSyntax);
		}
		this.log("Loading..");
	},
	encodeURL: function(allOptions) {
		var opt = Object.assign({}, ret.urlOptions);
		opt.code = encodeURIComponent(editor.toString());
		if (allOptions) {
			opt.currentParseOption = String(ret.currentParseOption);
			opt.currentOutputOption = String(ret.currentOutputOption);
			if (ret.useGodboltOnAssembler) opt.useGodboltOnAssembler = "true";
			opt.currentSyntax = String(ret.currentSyntax);
		}
		var newUrl = window.location.origin + window.location.pathname + "?" + new URLSearchParams(opt).toString();
		prompt("Copy", newUrl);
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
	currentSyntax: 0,
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
		ret.re_assemble = Module.cwrap('re_assemble', 'number', ['number', 'number', 'number', 'number', 'number', 'string', 'number']);
		ret.re_emulator = Module.cwrap('re_emulator', 'number', ['number', 'number', 'number', 'number']);
		ret.re_disassemble = Module.cwrap('re_disassemble', 'number', ['number', 'number', 'number', 'number', 'number', 'string', 'number', 'number']);
		ret.re_get_hex_buffer = Module.cwrap('re_get_hex_buffer', 'number', []);
		ret.re_get_err_buffer = Module.cwrap('re_get_err_buffer', 'number', []);
		ret.re_get_str_buffer = Module.cwrap('re_get_str_buffer', 'number', []);
		ret.re_get_mem_buffer = Module.cwrap('re_get_mem_buffer', 'number', []);
		ret.get_buffer_contents = Module.cwrap('get_buffer_contents', 'string', ['number']);
		ret.get_buffer_contents_raw = Module.cwrap('get_buffer_contents', 'number', ['number']);
		ret.get_buffer_data_length = Module.cwrap('get_buffer_data_length', 'number', ['number']);
		ret.parser_to_buf = Module.cwrap('parser_to_buf', 'number', ['string', 'number', 'number', 'number']);
		ret.buffer_to_buffer = Module.cwrap('buffer_to_buffer', 'void', ['number', 'number', 'number']);

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
						intel: true,
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
};
ret.init();

setupDropDown(document.querySelector("#hex-dropdown"), document.querySelector("#hex-dropdown-box"));
setupDropDown(document.querySelector("#examples-dropdown"), document.querySelector("#examples-dropdown-box"));
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
	editor.innerHTML = editor.innerHTML.replace(
		/(https?:\/\/[^\s<\"]+)/g,
		url => `<a href="${url}" contenteditable="false" target="_blank" rel="noopener noreferrer">${url}</a>`
	);
};

let editor = CodeJar(document.querySelector(".editor"), highlight, {tab: '\t'});

// Set editor text if empty (will not be if window was duplicated)
if (ret.urlOptions.hasOwnProperty("code")) {
	editor.updateCode(decodeURIComponent(ret.urlOptions.code));
}
if (editor.toString() == "") {
	editor.updateCode(ret.getExample("Hello World"));
}

function setBytes(hex_buf) {
	if (ret.currentOutputOption & ret.OUTPUT_AS_C_ARRAY) {
		document.querySelector("#bytes").value = "{" + ret.get_buffer_contents(hex_buf) + "}";
	} else {
		document.querySelector("#bytes").value = ret.get_buffer_contents(hex_buf);
	}
}

function finishAssembler(code, outBuf, errBuf, doneCallback) {
	var then = Date.now();
	var rc = ret.re_assemble(ret.currentArch, ret.currentBaseOffset, ret.currentSyntax, outBuf, errBuf, code, ret.currentOutputOption);
	var now = Date.now();
	if (rc != 0) {
		doneCallback(rc, now - then);
	} else {
		ret.log("Assembled in " + String(now - then) + "us");
		doneCallback(rc, now - then);
	}
}
function fullAssembler(code, outBuf, errBuf, doneCallback) {
	if (!code.endsWith("\n")) {
		// make file valid
		code += "\n";
	}
	if (ret.useGodboltOnAssembler) {
		ret.log("Sending code to Godbolt...");
		(async function() {
			var x = await ret.godbolt(ret.currentArch, code);
			if (x != null) {
				// This has to be done because of godbolt policy - we can't get JSON output
				var split = x.split("\nStandard error:\n");
				if (split.length == 1) {
					ret.log("No errors from Godbolt API.");
					// TODO: Feed in new code
					finishAssembler(code, outBuf, errBuf, doneCallback);
				} else {
					ret.log("Error message from Godbolt API:");
					ret.log(split[1]);
				}
			} else {
				// Request error
			}
		})();
	} else {
		finishAssembler(code, outBuf, errBuf, doneCallback);
	}
}

document.querySelector("#assemble").onclick = function() {
	if (ret.hex_buf == null || ret.err_buf == null) throw "NULL";
	ret.clearLog();
	var code = editor.toString();
	fullAssembler(code, ret.hex_buf, ret.err_buf, function(rc) {
		if (rc != 0) {
			ret.log(ret.get_buffer_contents(ret.err_buf));
		} else {
			setBytes(ret.hex_buf);
		}
	});
}

document.querySelector("#disassemble").onclick = function() {
	if (ret.hex_buf == null || ret.err_buf == null) throw "NULL";	
	ret.clearLog();
	var then = Date.now();
	var rc = ret.re_disassemble(ret.currentArch, ret.currentBaseOffset, ret.currentSyntax, ret.str_buf, ret.err_buf, document.querySelector("#bytes").value, ret.currentParseOption, ret.currentOutputOption);
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

	fullAssembler(code, ret.mem_buf, ret.err_buf, function(rc) {
		if (rc != 0) {
			ret.log(ret.get_buffer_contents(ret.err_buf));
		} else {
			ret.buffer_to_buffer(ret.hex_buf, ret.mem_buf, ret.currentOutputOption);
			setBytes(ret.hex_buf);

			rc = ret.re_emulator(ret.currentArch, ret.currentBaseOffset, ret.mem_buf, ret.str_buf);
			ret.log(ret.get_buffer_contents(ret.str_buf));
		}
	});
}

document.querySelector("#hex-dropdown").onclick = function(e) {
	if (!document.querySelector("#hex-dropdown-box").contains(e.target)) {
		if (ret.hex_buf == null) throw "NULL";	
		ret.clearLog();
		var rc = ret.parser_to_buf(document.querySelector("#bytes").value, ret.hex_buf, ret.currentParseOption, ret.currentOutputOption);
		if (rc != 0) {
			ret.log("Failed to parse bytes");
		} else {
			setBytes(ret.hex_buf);
			var output_as = "", parse_as = "";
			if (ret.currentParseOption & ret.PARSE_AS_U8) parse_as = "u8";
			if (ret.currentParseOption & ret.PARSE_AS_U16) parse_as = "u16";
			if (ret.currentParseOption & ret.PARSE_AS_U32) parse_as = "u32";
			if (ret.currentParseOption & ret.PARSE_AS_AUTO) parse_as = "auto";
			if (ret.currentParseOption & ret.PARSE_AS_U64) parse_as = "u64";
			if (ret.currentParseOption & ret.PARSE_AS_BASE_10) parse_as = ", base10";

			if (ret.currentOutputOption & ret.OUTPUT_AS_U8) output_as = "u8";
			if (ret.currentOutputOption & ret.OUTPUT_AS_U16) output_as = "u16";
			if (ret.currentOutputOption & ret.OUTPUT_AS_U32) output_as = "u32";
			if (ret.currentOutputOption & ret.OUTPUT_AS_AUTO) output_as = "auto";
			if (ret.currentOutputOption & ret.OUTPUT_AS_U64) output_as = "u64";
			if (ret.currentOutputOption & ret.OUTPUT_AS_C_ARRAY) output_as = "c array";

			ret.log("Formatted hex (parse as '" + parse_as + "') (output as '" + output_as + "')");
		}
	}
}

document.querySelector("#save-button").onclick = function() {
	if (ret.mem_buf == null) throw "NULL";	
	ret.clearLog();
	var rc = ret.parser_to_buf(document.querySelector("#bytes").value, ret.mem_buf, ret.currentParseOption, ret.currentOutputOption);
	if (rc != 0) {
		ret.log("Failed to parse bytes");
	} else {
		var ptr = ret.get_buffer_contents_raw(ret.mem_buf);
		var len = ret.get_buffer_data_length(ret.mem_buf);
		// Latest emsdk seems to not put HEAPU8 in Module (?)
		ret.downloadFile(HEAPU8.subarray(ptr, ptr + len));
	}
}

document.querySelector("#base-address").value = "0x" + (ret.currentBaseOffset).toString(16);
document.querySelector("#base-address").onkeyup = function() {
	if (Number(this.value) != NaN) {
		ret.currentBaseOffset = Number(this.value);
	}
}

document.querySelector("#settings-btn").onclick = function() {
	document.querySelector("#popup").style.display = "block";
}
document.querySelector("#share-btn").onclick = function() {
	ret.encodeURL(false);
}
document.querySelector("#all-url-options").onclick = function() {
	ret.encodeURL(true);
}
document.querySelector("#popup-close").onclick = function() {
	document.querySelector("#popup").style.display = "none";
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
	if (index == 3) option = ret.OUTPUT_AS_C_ARRAY;
	ret.currentOutputOption = option; // currently only one option is allowed
	//ret.currentOutputOption = (ret.currentOutputOption & (~0x1f)) | option;
});

setupRadio("x86_syntax", 0, function(index, value, e) {
	var option = 0;
	if (index == 0) option = ret.SYNTAX_INTEL;
	if (index == 1) option = ret.SYNTAX_ATT;
	if (index == 2) option = ret.SYNTAX_NASM;
	if (index == 3) option = ret.SYNTAX_MASM;
	if (index == 4) option = ret.SYNTAX_GAS;
	ret.currentSyntax = option;
});

document.querySelector("#parseccomments").checked = (ret.currentParseOption & ret.PARSE_C_COMMENTS) != 0;
document.querySelector("#parseccomments").onchange = function() {
	if (this.checked) {
		ret.currentParseOption |= ret.PARSE_C_COMMENTS;
	} else {
		ret.currentParseOption &= ~(ret.PARSE_C_COMMENTS);
	}
}

document.querySelector("#usegodbolt").checked = ret.useGodboltOnAssembler;
document.querySelector("#usegodbolt").onchange = function() {
	if (this.checked) {
		ret.useGodboltOnAssembler = true;
	} else {
		ret.useGodboltOnAssembler = false;
	}
}

function fillExamples() {
	document.querySelector("#examples-dropdown-box").innerHTML = "";
	var examples = ret.getExamples();
	for (var i = 0; i < examples.length; i++) {
		var el = document.createElement("div");
		el.className = "btn";
		el.exampleName = examples[i].name;
		el.onclick = function() {
			editor.updateCode(ret.getExample(this.exampleName));
		}
		el.innerText = examples[i].name;
		document.querySelector("#examples-dropdown-box").appendChild(el);
	}
}
fillExamples();

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
