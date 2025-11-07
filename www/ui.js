// Prevent selection while dragging
function pauseEvent(e) {
    if (e.stopPropagation) e.stopPropagation();
    if (e.preventDefault) e.preventDefault();
    e.cancelBubble = true;
    e.returnValue = false;
    return false;
}

function createResizeBar(leftPanel, rightPanel, separator, horizontal = true) {
	function resizePanel(event) {
		let prevX = event.x;
		let prevY = event.y;
		let lefthPanelWidth = leftPanel.getBoundingClientRect().width;
		let lefthPanelHeight = leftPanel.getBoundingClientRect().height;
		let rightPanelWidth = rightPanel.getBoundingClientRect().width;
		let rightPanelHeight = rightPanel.getBoundingClientRect().height;
		function mousemove(e) {
			leftPanel.style.flex = "none";
			if (horizontal) {
				let distance =  e.x - prevX;
				// Only resize left panel, right panel will flex
				leftPanel.style.width = String(lefthPanelWidth + distance) + "px";
			} else {
				let distance =  e.y - prevY;
				leftPanel.style.height = String(lefthPanelHeight + distance) + "px";
			}
	
			leftPanel.style.userSelect = "none";
			rightPanel.style.userSelect = "none";

			pauseEvent(e);
		}
	
		function mouseup() {
			leftPanel.style.userSelect = "auto";
			rightPanel.style.userSelect = "auto";
	
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
	let names = document.getElementsByName(elementName);
	for (let i = 0; i < names.length; i++) {
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
			for (let x = 0; x < names.length; x++) {
				if (x != this.index) {
					names[x].checked = false;
					names[x].classList.remove("radio-checked");
				}
			}
			callback(this.index, this.value, this);
		}
	}
}

function setupRadioFromMap(elementName, initialOptionValue, map, callback) {
	let defaultOpt = Object.keys(map).find(k => map[k] === initialOptionValue);
	setupRadio(elementName, defaultOpt, function(index, value, e) {
		callback(map[index]);
	});
}

function setupWidgets() {
	setupDropDown(document.querySelector("#hex-dropdown"), document.querySelector("#hex-dropdown-box"));
	setupDropDown(document.querySelector("#x86-dropdown"), document.querySelector("#x86-dropdown-box"));
	setupDropDown(document.querySelector("#riscv-dropdown"), document.querySelector("#riscv-dropdown-box"));
	setupDropDown(document.querySelector("#ppc-dropdown"), document.querySelector("#ppc-dropdown-box"));
	setupDropDown(document.querySelector("#examples-dropdown"), document.querySelector("#examples-dropdown-box"));
	setupDropDown(document.querySelector("#help-dropdown"), document.querySelector("#help-dropdown-box"));
	setupDropDown(document.querySelector("#arch-select"), document.querySelector("#arch-dropdown-box"), false, true);

	createResizeBar(
		document.querySelector("#panel1"),
		document.querySelector("#right-column"),
		document.querySelector("#hseparator")
	);
	createResizeBar(
		document.querySelector("#panel2"),
		document.querySelector("#panel3"),
		document.querySelector("#vseparator"),
		vertical = false
	);
}
setupWidgets();

// Change menu color, syntax, title, etc depending on arch
function updatePageArch() {
	if (ret.currentArch == ret.ARCH_ARM64) {
		document.querySelector("#arch-select-text").innerText = "Arm64";
		document.querySelector("#menu").style.background = "rgb(23 55 81)"; // arm corp logo
		document.querySelector("#asm").classList.add("language-armasm2");
	} else if (ret.currentArch == ret.ARCH_X86) {
		document.querySelector("#arch-select-text").innerText = "x86";
		document.querySelector("#menu").style.background = "rgb(97 36 48)"; // amd logo
		document.querySelector("#asm").classList.add("language-x86asm2");
		document.querySelector("#x86-dropdown").style.display = "flex";
	} else if (ret.currentArch == ret.ARCH_ARM32) {
		document.querySelector("#arch-select-text").innerText = "Arm32";
		document.querySelector("#menu").style.background = "rgb(19 73 64)"; // acorn computer logo
		document.querySelector("#asm").classList.add("language-armasm2");
	} else if (ret.currentArch == ret.ARCH_ARM32_THUMB) {
		document.querySelector("#arch-select-text").innerText = "Arm32 Thumb";
		document.querySelector("#menu").style.background = "rgb(24 91 83)"; // acorn computer logo
		document.querySelector("#asm").classList.add("language-armasm2");
	} else if (ret.currentArch == ret.ARCH_RISCV) {
		document.querySelector("#arch-select-text").innerText = "RISC-V";
		document.querySelector("#menu").style.background = "rgb(179 148 84)"; // risc-v logo
		document.querySelector("#asm").classList.add("language-armasm2");
		document.querySelector("#riscv-dropdown").style.display = "flex";
	} else if (ret.currentArch == ret.ARCH_POWERPC) {
		document.querySelector("#arch-select-text").innerText = "PowerPC";
		document.querySelector("#menu").style.background = "rgb(164 87 69)"; // powerpc logo
		document.querySelector("#asm").classList.add("language-armasm2");
		document.querySelector("#ppc-dropdown").style.display = "flex";
	}
}
updatePageArch();

function escape_html(s) {
	return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// The highlight function runs on every keypress - it should be fast
const highlight = editor => {
	delete editor.dataset.highlighted;
	editor.innerHTML = escape_html(editor.textContent);
	hljs.highlightElement(editor);
	// Only read/write innerHTML on hljs-comment elements to improve performance
	let comments = editor.getElementsByClassName("hljs-comment");
	for (let i = 0; i < comments.length; i++) {
		comments[i].innerHTML = comments[i].innerHTML.replace(
			/(https?:\/\/[^\s<\"]+)/g,
			url => `<a href="${url}" contenteditable="false" target="_blank" rel="noopener noreferrer">${url}</a>`
		);
	}
};

let editor = CodeJar(document.querySelector("#asm"), highlight, {tab: '\t'});

// Set editor text if empty (will not be if window was duplicated)
if (ret.urlOptions.hasOwnProperty("code")) {
	editor.updateCode(decodeURIComponent(ret.urlOptions.code));
} else if (ret.urlOptions.hasOwnProperty("codeb64")) {
	editor.updateCode(atob(ret.urlOptions.codeb64));
}
if ((ret.urlOptions.hasOwnProperty("theme") && ret.urlOptions.theme == "light")
		|| !(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
	let prefix = "";
	if (ret.currentArch != ret.DEFAULT_ARCH) prefix = "../";
	document.querySelector("#themelink").href = prefix + "light-theme.css";
}
if (editor.toString() == "") {
	editor.updateCode(ret.getExample("Hello World"));
}

function setBytes(hex_buf) {
	if (ret.baseOutputOption == ret.OUTPUT_AS_C_ARRAY) {
		document.querySelector("#bytes").value = "{" + ret.get_buffer_contents(hex_buf) + "}";
	} else {
		document.querySelector("#bytes").value = ret.get_buffer_contents(hex_buf);
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
			let x = await ret.godbolt(ret.currentArch, code);
			if (x != null) {
				// This has to be done because of a godbolt CORS policy - we can't get JSON output
				let split = x.split("\nStandard error:\n");
				if (split.length == 1) {
					ret.log("No errors from Godbolt API.");
					// TODO: Feed in new code
					let t = ret.assemble(code, outBuf, errBuf);
					doneCallback(t[0], t[1]);
				} else {
					ret.log("Error message from Godbolt API:");
					ret.log(split[1]);
				}
			} else {
				// Request error
			}
		})();
	} else {
		let t = ret.assemble(code, outBuf, errBuf);
		doneCallback(t[0], t[1]);
	}
}

document.querySelector("#assemble").onclick = function() {
	if (ret.hex_buf == null || ret.err_buf == null) throw "NULL";
	ret.clearLog();
	let code = editor.toString();
	fullAssembler(code, ret.hex_buf, ret.err_buf, function(rc, time) {
		if (rc != 0) {
			ret.log(ret.get_buffer_contents(ret.err_buf));
			document.querySelector("#bytes").value = "";
		} else {
			ret.log("Assembled in " + String(time) + "us");
			setBytes(ret.hex_buf);
		}
	});
}

document.querySelector("#disassemble").onclick = function() {
	if (ret.hex_buf == null || ret.err_buf == null) throw "NULL";	
	ret.clearLog();
	let obj = ret.disassemble(document.querySelector("#bytes").value, ret.str_buf, ret.err_buf);
	let rc = obj[0];
	if (rc != 0) {
		ret.log(ret.get_buffer_contents(ret.err_buf));
	} else {
		editor.updateCode(ret.get_buffer_contents(ret.str_buf));
		ret.log("Disassembled in " + String(obj[1]) + "us");
	}
}

document.querySelector("#run").onclick = function() {
	if (ret.mem_buf == null || ret.err_buf == null || ret.str_buf == null) throw "NULL";	
	ret.clearLog();
	if (ret.re_is_unicorn_supported() == 0) {
		ret.log("This target doesn't have Unicorn VM support.");
		return;
	}
	let code = editor.toString();

	fullAssembler(code, ret.hex_mem_mirror_buf, ret.err_buf, function(rc) {
		if (rc != 0) {
			ret.log(ret.get_buffer_contents(ret.err_buf));
			document.querySelector("#bytes").value = "";
		} else {
			setBytes(ret.hex_buf);
			let rc = ret.emulator(ret.mem_buf, ret.str_buf);
			ret.log(ret.get_buffer_contents(ret.str_buf));
		}
	});
}

document.querySelector("#hex-dropdown").onclick = function(e) {
	if (!document.querySelector("#hex-dropdown-box").contains(e.target)) {
		if (ret.hex_buf == null) throw "NULL";	
		ret.clearLog();
		let rc = ret.parser_to_buf(document.querySelector("#bytes").value, ret.hex_buf, ret.getParseOption(), ret.getOptionOption() | ret.OUTPUT_SPLIT_BY_FOUR);
		if (rc != 0) {
			ret.log("Failed to parse bytes");
		} else {
			setBytes(ret.hex_buf);
			let output_as = "auto", parse_as = "auto";
			if (ret.baseParseOption == ret.PARSE_AS_U8) parse_as = "u8";
			if (ret.baseParseOption == ret.PARSE_AS_U16) parse_as = "u16";
			if (ret.baseParseOption == ret.PARSE_AS_U32) parse_as = "u32";
			if (ret.baseParseOption == ret.PARSE_AS_AUTO) parse_as = "auto";
			if (ret.baseParseOption == ret.PARSE_AS_U64) parse_as = "u64";
			if (ret.baseParseOption == ret.PARSE_AS_BASE_10) parse_as += ", base10";

			if (ret.baseOutputOption == ret.OUTPUT_AS_U8) output_as = "u8";
			if (ret.baseOutputOption == ret.OUTPUT_AS_U16) output_as = "u16";
			if (ret.baseOutputOption == ret.OUTPUT_AS_U32) output_as = "u32";
			if (ret.baseOutputOption == ret.OUTPUT_AS_AUTO) output_as = "auto";
			if (ret.baseOutputOption == ret.OUTPUT_AS_U64) output_as = "u64";
			if (ret.baseOutputOption == ret.OUTPUT_AS_C_ARRAY) output_as = "c array";

			ret.log("Formatted hex (parse as '" + parse_as + "') (output as '" + output_as + "')");
		}
	}
}

document.querySelector("#save-button").onclick = function() {
	if (ret.mem_buf == null) throw "NULL";	
	ret.clearLog();
	let rc = ret.parser_to_buf(document.querySelector("#bytes").value, ret.mem_buf, ret.getParseOption(), ret.getOptionOption());
	if (rc != 0) {
		ret.log("Failed to parse bytes");
	} else {
		let ptr = ret.get_buffer_contents_raw(ret.mem_buf);
		let len = ret.get_buffer_data_length(ret.mem_buf);
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
	document.querySelector("#popup").style.display = "flex";
}
document.querySelector("#share-btn").onclick = function() {
	let txt = document.querySelector("#copy-textarea");
	document.querySelector("#copy-popup").style.display = "flex";
	txt.value = ret.encodeURL(true);
	txt.select();
	txt.setSelectionRange(0, 99999);
}
document.querySelector("#popup-close").onclick = function() {
	document.querySelector("#popup").style.display = "none";
}
document.querySelector("#copy-popup-button").onclick = function() {
	document.querySelector("#copy-popup").style.display = "none";
}

setupRadioFromMap("select_parse_as", ret.baseParseOption, [
	ret.PARSE_AS_AUTO,
	ret.PARSE_AS_U8,
	ret.PARSE_AS_U16,
	ret.PARSE_AS_U32,
], function(value) {
	ret.baseParseOption = value;
});
setupRadioFromMap("select_output_as", ret.baseOutputOption, [
	ret.OUTPUT_AS_AUTO,
	ret.OUTPUT_AS_U8,
	ret.OUTPUT_AS_U32,
	ret.OUTPUT_AS_C_ARRAY,
	ret.OUTPUT_AS_BINARY,
], function(value) {
	ret.baseOutputOption = value;
});
setupRadioFromMap("x86_syntax", ret.currentSyntax, [
	ret.SYNTAX_INTEL,
	ret.SYNTAX_ATT,
	ret.SYNTAX_NASM,
	ret.SYNTAX_MASM,
	ret.SYNTAX_GAS,
], function(value) {
	ret.currentSyntax = value;
	fillExamples();
});
setupRadioFromMap("x86_bits", ret.bits, [
	64,
	32,
	16,
], function(value) {
	ret.bits = value;
});
setupRadioFromMap("riscv_bits", ret.bits, [
	64,
	32,
], function(value) {
	ret.bits = value;
});
setupRadioFromMap("ppc_bits", ret.bits, [
	64,
	32,
], function(value) {
	ret.bits = value;
});
setupRadioFromMap("ppc_endian", ret.endian, [
	ret.BIG_ENDIAN,
	ret.LITTLE_ENDIAN,
], function(value) {
	ret.endian = value;
});

document.querySelector("#parseccomments").checked = ret.parseCComments;
document.querySelector("#parseccomments").onchange = function() {
	ret.parseCComments = this.checked;
}

document.querySelector("#splitbyinst").checked = ret.splitBytesByInstruction;
document.querySelector("#splitbyinst").onchange = function() {
	ret.splitBytesByInstruction = this.checked;
}

document.querySelector("#usegodbolt").checked = ret.useGodboltOnAssembler;
document.querySelector("#usegodbolt").onchange = function() {
	ret.useGodboltOnAssembler = this.checked;
}

document.querySelector("#riscvc").checked = ret.riscvc;
document.querySelector("#riscvc").onchange = function() {
	ret.riscvc = this.checked;
}

function fillExamples() {
	document.querySelector("#examples-dropdown-box").innerHTML = "";
	let examples = ret.getExamples();
	for (let i = 0; i < examples.length; i++) {
		let el = document.createElement("div");
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

// Try to get shortcuts working
document.addEventListener("keydown", keyCapt, false); 
document.addEventListener("keyup", keyCapt, false);
document.addEventListener("keypress", keyCapt, false);
function keyCapt(e) {
	if (typeof window.event != "undefined") {
		e = window.event;	
	}
	if (e.type == "keydown" && (e.key == "F1")) {
		e.preventDefault();
		document.querySelector("#assemble").click();
	}
	if (e.type == "keydown" && (e.key == "F9")) {
		e.preventDefault();
		document.querySelector("#run").click();
	}
	if (e.type == "keydown" && (e.key == "Escape")) {
		e.preventDefault();
		document.querySelector("#copy-popup").style.display = "none";
		document.querySelector("#popup").style.display = "none";
	}
}
