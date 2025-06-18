const arm64_demo =
`
adr x1, string
top:
	ldrb w0, [x1]
	cmp w0, #0x0
	beq end
	svc #0x0
	add x1, x1, #0x1
	b top
end:

b skip
string:
.ascii "Hello, World\\n"
.byte 0
.align 4
skip:
`;
const x86_64_demo =
`
mov eax, 10h
`;

// Prevent selection while dragging
function pauseEvent(e){
    if(e.stopPropagation) e.stopPropagation();
    if(e.preventDefault) e.preventDefault();
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

function setupDropDown(hoverButton, box) {
	hoverButton.addEventListener("mouseenter", function() {
		box.style.display = "flex";
	})
	hoverButton.addEventListener("mouseleave", function() {
		box.style.display = "none";
	})
	box.addEventListener("mouseup", function() {
		box.style.display = "none";
	})
}

const ret = {
	init: function() {
		this.currentArch = this.checkArch();
	},
	checkArch: function() {
		if (window.location.href.endsWith("arm") || window.location.href.endsWith("arm32")) {
			return ret.ARCH_ARM32;
		} else if (window.location.href.endsWith("arm64")) {
			return ret.ARCH_ARM64;
		} else if (window.location.href.endsWith("riscv")) {
			return ret.ARCH_RISCV64;
		} else if (window.location.href.endsWith("x86")) {
			return ret.ARCH_X86_64;
		} else {
			return ret.ARCH_ARM64;
		}
	},
	currentArch: 0,
	currentBaseOffset: 0,

	ARCH_ARM64: 0,
	ARCH_ARM32: 1,
	ARCH_X86: 2,
	ARCH_X86_64: 3,
	ARCH_RISCV32: 4,
	ARCH_RISCV64: 5,
	ARCH_WASM: 6,

	clearLog: function(str) {
		document.querySelector("#log").value = "";
	},
	log: function(str) {
		document.querySelector("#log").value += str + "\n";
	},

	re_log: Module.cwrap('re_log', 'void', ['number', 'string']),
	re_init_globals: Module.cwrap('re_init_globals', 'void', []),
	re_assemble: Module.cwrap('re_assemble', 'number', ['number', 'number', 'number', 'number', 'string']),
	re_disassemble: Module.cwrap('re_disassemble', 'number', ['number', 'number', 'number', 'number', 'string']),
	re_get_hex_buffer: Module.cwrap('re_get_hex_buffer', 'number', []),
	re_get_err_buffer: Module.cwrap('re_get_err_buffer', 'number', []),
	re_get_str_buffer: Module.cwrap('re_get_str_buffer', 'number', []),
	get_buffer_contents: Module.cwrap('get_buffer_contents', 'string', ['number']),

	err_buf: null,
	hex_buf: null,
	str_buf: null,

	main: function() {
		ret.re_init_globals();
		ret.err_buf = ret.re_get_err_buffer();
		ret.hex_buf = ret.re_get_hex_buffer();
		ret.str_buf = ret.re_get_str_buffer();

		ret.clearLog();
		ret.log("Ret v4");
		ret.log("Running in WebAssembly with Capstone, keystone, and Unicorn.");
	},

	godbolt: async function(arch, assemblyCode) {
		var compiler = "";
		if (arch == ret.ARCH_ARM64) {
			compiler = "gnuasarm64g1510";
		} else if (arch == ret.ARCH_ARM32) {
			compiler = "gnuasarmhfg54";
		} else if (arch == ret.ARCH_X86_64) {
			compiler = "gnuassnapshot";
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
					userArguments: '',
					filters: {
						intel: false,
						comments: true,
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

const highlight = editor => {
	editor.textContent = editor.textContent
	hljs.highlightBlock(editor)
};

let editor = CodeJar(document.querySelector(".editor"), highlight);

setupDropDown(document.querySelector("#hex-dropdown"), document.querySelector("#hex-dropdown-box"));
setupDropDown(document.querySelector("#help-dropdown"), document.querySelector("#help-dropdown-box"));

createResizeBar(
	document.querySelector("#panel1"),
	document.querySelector("#right-column"),
	document.querySelector("#hseparator")
);

// Change menu color depending on arch
if (ret.currentArch == ret.ARCH_ARM64) {
	document.querySelector("#menu").style.background = "rgb(23 55 81)";
} else if (ret.currentArch == ret.ARCH_X86 || ret.currentArch == ret.ARCH_X86_64) {
	document.querySelector("#menu").style.background = "rgb(97 36 48)";
}

document.querySelector("#assemble").onclick = function() {
	if (ret.hex_buf == null || ret.err_buf == null) throw "NULL";
	ret.clearLog();
	var code = editor.toString();
	var then = Date.now();
	var rc = ret.re_assemble(ret.currentArch, ret.currentBaseOffset, ret.hex_buf, ret.err_buf, code);
	var now = Date.now();
	if (rc != 0) {
		ret.log("Capstone error, validating code through Godbolt...");
		(async function() {
			var x = await ret.godbolt(ret.currentArch, code);
			if (x != null) {
				ret.log(x);
			}
		})();
	} else {
		document.querySelector("#bytes").value = ret.get_buffer_contents(ret.hex_buf);
		ret.log("Assembled in " + String(now - then) + "us");
	}
}

document.querySelector("#disassemble").onclick = function() {
	if (ret.hex_buf == null || ret.err_buf == null) throw "NULL";	
	ret.clearLog();
	var code = editor.toString();
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

document.querySelector("#base-address").value = "0x" + (ret.currentBaseOffset).toString(16);
document.querySelector("#base-address").onkeyup = function() {
	if (Number(this.value) != NaN) {
		ret.currentBaseOffset = Number(this.value);
	}
}

// Set editor text if empty (will not be if window was duplicated)
if (editor.toString() == "") {
	switch (ret.currentArch) {
		case ret.ARCH_ARM64: editor.updateCode(arm64_demo.trim()); break;
		case ret.ARCH_X86_64: editor.updateCode(x86_64_demo.trim()); break;
	}
}

