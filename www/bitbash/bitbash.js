var examples = [
	'name CR0\nsize 32\n[31] = PG\n[30] = CD\n[29] = NW\n[16] = WP\n[5] = NE\n[4] = ET\n[3] = TS\n[2] = EM\n[1] = MP\n[0] = PE',
	'name TCR_EL1\nsize 64\n[52] = TBID1\n[51] = TBID0\n[40] = HD\nif HD == 0b0: "Disable"\nif HD == 0b1: "Enable"\n[39] = HA\nif HA == 0b0: "Disable"\nif HA == 0b1: "Enable"\n[38] = TBI1\nif TBI1 == 0b0: "Used"\nif TBI1 == 0b1: "Ignored"\n[37] = TBI0\nif TBI0 == 0b0: "Used"\nif TBI0 == 0b1: "Ignored"\n[36] = AS\nif AS == 0b0: "ASID8Bits"\nif AS == 0b1: "ASID16Bits"\n[34:32] = IPS\nif IPS == 0b000: "Bits_32"\nif IPS == 0b001: "Bits_36"\nif IPS == 0b010: "Bits_40"\nif IPS == 0b011: "Bits_42"\nif IPS == 0b100: "Bits_44"\nif IPS == 0b101: "Bits_48"\nif IPS == 0b110: "Bits_52"\n[31:30] = TG1\nif TG1 == 0b10: "KiB_4"\nif TG1 == 0b01: "KiB_16"\nif TG1 == 0b11: "KiB_64"\n[29:28] = SH1\nif SH1 == 0b00: "None"\nif SH1 == 0b10: "Outer"\nif SH1 == 0b11: "Inner"\n[27:26] = ORGN1\nif ORGN1 == 0b00: "NonCacheable"\nif ORGN1 == 0b01: "WriteBack_ReadAlloc_WriteAlloc_Cacheable"\nif ORGN1 == 0b10: "WriteThrough_ReadAlloc_NoWriteAlloc_Cacheable"\nif ORGN1 == 0b11: "WriteBack_ReadAlloc_NoWriteAlloc_Cacheable"\n[25:24] = IRGN1\nif IRGN1 == 0b00: "NonCacheable"\nif IRGN1 == 0b01: "WriteBack_ReadAlloc_WriteAlloc_Cacheable"\nif IRGN1 == 0b10: "WriteThrough_ReadAlloc_NoWriteAlloc_Cacheable"\nif IRGN1 == 0b11: "WriteBack_ReadAlloc_NoWriteAlloc_Cacheable"\n[23] = EPD1\nif EPD1 == 0b0: "EnableTTBR1Walks"\nif EPD1 == 0b1: "DisableTTBR1Walks"\n[22] = A1\nif A1 == 0b0: "TTBR0"\nif A1 == 0b1: "TTBR1"\n[21:16] = T1SZ\n[15:14] = TG0\nif TG0 == 0b00: "KiB_4"\nif TG0 == 0b10: "KiB_16"\nif TG0 == 0b01: "KiB_64"\n[13:12] = SH0\nif SH0 == 0b00: "None"\nif SH0 == 0b10: "Outer"\nif SH0 == 0b11: "Inner"\n[11:10] = ORGN0\nif ORGN0 == 0b00: "NonCacheable"\nif ORGN0 == 0b01: "WriteBack_ReadAlloc_WriteAlloc_Cacheable"\nif ORGN0 == 0b10: "WriteThrough_ReadAlloc_NoWriteAlloc_Cacheable"\nif ORGN0 == 0b11: "WriteBack_ReadAlloc_NoWriteAlloc_Cacheable"\n[9:8] = IRGN0\nif IRGN0 == 0b00: "NonCacheable"\nif IRGN0 == 0b01: "WriteBack_ReadAlloc_WriteAlloc_Cacheable"\nif IRGN0 == 0b10: "WriteThrough_ReadAlloc_NoWriteAlloc_Cacheable"\nif IRGN0 == 0b11: "WriteBack_ReadAlloc_NoWriteAlloc_Cacheable"\n[7] = EPD0\nif EPD0 == 0b0: "EnableTTBR0Walks"\nif EPD0 == 0b1: "DisableTTBR0Walks"\n[5:0] = T0SZ',
	'name CR4\nsize 32\n[24] = PKS\n[23] = CET\n[22] = PKE\n[21] = SMAP\n[20] = SMEP\n[18] = OSXSAVE\n[17] = PCIDE\n[16] = FSGSBASE\n[14] = SMXE\n[13] = VMXE\n[12] = LA57\n[11] = UMIP\n[10] = OSXMMEXCPT\n[9] = OSFXSR\n[8] = PCE\n[7] = PGE\n[6] = MCE\n[5] = PAE\n[4] = PSE\n[3] = DE\n[2] = TSD\n[1] = PVI\n[0] = VME\nif PKS == 0b0: "Protection Keys Supervisor disabled"\nif PKS == 0b1: "Protection Keys Supervisor enabled"\nif CET == 0b0: "Control-flow Enforcement Technology disabled"\nif CET == 0b1: "Control-flow Enforcement Technology enabled"\nif PKE == 0b0: "Protection Keys disabled"\nif PKE == 0b1: "Protection Keys enabled"\nif SMAP == 0b0: "Supervisor Mode Access Prevention disabled"\nif SMAP == 0b1: "Supervisor Mode Access Prevention enabled"\nif SMEP == 0b0: "Supervisor Mode Exec Protection disabled"\nif SMEP == 0b1: "Supervisor Mode Exec Protection enabled"\nif OSXSAVE == 0b0: "XSAVE disabled"\nif OSXSAVE == 0b1: "XSAVE enabled"\nif PCIDE == 0b0: "PCID disabled"\nif PCIDE == 0b1: "PCID enabled"\nif FSGSBASE == 0b0: "FSGSBASE disabled"\nif FSGSBASE == 0b1: "FSGSBASE enabled"\nif SMXE == 0b0: "SMX disabled"\nif SMXE == 0b1: "SMX enabled"\nif VMXE == 0b0: "VMX disabled"\nif VMXE == 0b1: "VMX enabled"\nif LA57 == 0b0: "4-level paging"\nif LA57 == 0b1: "5-level paging"\nif UMIP == 0b0: "User-Mode Instruction Prevention disabled"\nif UMIP == 0b1: "User-Mode Instruction Prevention enabled"\nif OSXMMEXCPT == 0b0: "Unmasked SIMD FP exceptions disabled"\nif OSXMMEXCPT == 0b1: "Unmasked SIMD FP exceptions enabled"\nif OSFXSR == 0b0: "FXSAVE/FXRSTOR disabled"\nif OSFXSR == 0b1: "FXSAVE/FXRSTOR enabled"\nif PCE == 0b0: "Performance monitoring disabled"\nif PCE == 0b1: "Performance monitoring enabled"\nif PGE == 0b0: "Page global disabled"\nif PGE == 0b1: "Page global enabled"\nif MCE == 0b0: "Machine Check Exception disabled"\nif MCE == 0b1: "Machine Check Exception enabled"\nif PAE == 0b0: "Physical Address Extension disabled"\nif PAE == 0b1: "Physical Address Extension enabled"\nif PSE == 0b0: "Page size extension disabled"\nif PSE == 0b1: "Page size extension enabled"\nif DE == 0b0: "Debugging extensions disabled"\nif DE == 0b1: "Debugging extensions enabled"\nif TSD == 0b0: "Time stamp disabled"\nif TSD == 0b1: "Time stamp enabled"\nif PVI == 0b0: "Protected-mode virtual interrupts disabled"\nif PVI == 0b1: "Protected-mode virtual interrupts enabled"\nif VME == 0b0: "Virtual 8086 mode extensions disabled"\nif VME == 0b1: "Virtual 8086 mode extensions enabled"',
];	

function bitmask(hi, lo) {
	let w = hi - lo + 1;
	if (w >= 32) return 0xFFFFFFFF >>> 0;
	return ((1 << w) - 1) << lo >>> 0;
}

function parseLanguage(code) {
	let reg = {
		"size": 32,
		"fields": []
	};

	function findField(name) {
		for (let i in reg.fields) {
			if (reg.fields[i].name == name) return reg.fields[i];
		}
		throw "Didn't find field '" + name + "'";
	}
	
	let split = code.split("\n");
	let reg_name = /name (.+)/;
	let reg_size = /size (.+)/;
	let set_bitfield_name = /\[([0-9]+):([0-9]+)\] = (.+)/;
	let set_bitfield_name_bit = /\[([0-9]+)\] = (.+)/;
	let case_bitfield_value = /if (.+) == ([xb0-9a-zA-Z]+): "(.+)"/;
	for (let i = 0; i < split.length; i++) {
		let match = split[i].match(set_bitfield_name);
		if (match) {
			reg.fields.push({
				"name": match[3],
				"top": Number(match[1]),
				"bottom": Number(match[2]),
				"descriptions": [],
			});
			continue;
		}
		match = split[i].match(set_bitfield_name_bit);
		if (match) {
			reg.fields.push({
				"name": match[2],
				"top": Number(match[1]),
				"bottom": Number(match[1]),
				"descriptions": [],
			});
			continue;
		}
		match = split[i].match(case_bitfield_value);
		if (match) {
			findField(match[1]).descriptions.push({
				"equals": Number(match[2]),
				"value": match[3],
			});
			continue;
		}
		match = split[i].match(reg_size);
		if (match) {
			reg.size = Number(match[1]);
			if (reg.size > 512) {
				throw "Unsupported register size";
			}
			continue;
		}
		match = split[i].match(reg_name);
		if (match) {
			reg.name = match[1];
			continue;
		}
		if (split[i].startsWith("//")) continue;
		//throw "Error on line: '" + split[i] + "'";
		//console.log(match);
	}

	return reg;
}

function HorizontalTableMaker() {
	return {
		tbl: document.createElement("table"),
		bits: document.createElement("tr"),
		levels: [],
		init: function(size) {
			this.tbl.className = "bit-table";
			this.tbl.appendChild(this.bits);
			//this.tbl.width = "100%";
			this.tbl.setAttribute("cellspacing", "0");
			this.tbl.setAttribute("cellpadding", "4");
		},
		addBit: function(bit) {
			let th = document.createElement("th");
			this.bits.appendChild(th);
			return th;
		},
		addBox: function(top, bottom, level) {
			let th = document.createElement("th");
			th.colSpan = top - bottom + 1;
			// Maintain a list of columns to add to for each level
			if (this.levels[level] == undefined) {
				this.levels[level] = document.createElement("tr");
				this.tbl.appendChild(this.levels[level]);
			}
			this.levels[level].appendChild(th);
			return th;
		}
	};
}

function VerticalTableMaker() {
	return {
		tbl: document.createElement("table"),
		init: function(size) {
			this.tbl.className = "bit-table";
			this.tbl.setAttribute("cellspacing", "0");
			this.tbl.setAttribute("cellpadding", "4");

			let tr = document.createElement("tr");
			this.tbl.appendChild(tr);
			let th = document.createElement("th");
			th.innerText = "Bit";
			tr.appendChild(th);
			th = document.createElement("th");
			th.innerText = "Bitmask";
			tr.appendChild(th);
			th = document.createElement("th");
			th.innerText = "Name";
			tr.appendChild(th);
			th = document.createElement("th");
			th.innerText = "Value";
			tr.appendChild(th);
		},
		addBit: function(bit) {
			let tr = document.createElement("tr");
			this.tbl.appendChild(tr);
			let th = document.createElement("th");
			tr.appendChild(th);
			return th;
		},
		addBox: function(top, bottom, level) {
			let th = document.createElement("th");
			th.rowSpan = top - bottom + 1;
			this.tbl.children[this.tbl.children.length - top - 1].appendChild(th);
			return th;
		}
	};
}

function createTable(reg, value, maker) {
	maker.init(reg.size);
	reg.fields.sort((a, b) => b.top - a.top);

	const LEVEL_CHECKBOXES = 0;
	const LEVEL_NAME = 1;
	const LEVEL_VALUE = 2;
	const LEVEL_BITMASK = 3;

	function setupBitMaskEntry(top, bottom) {
		let e = maker.addBox(top, bottom, LEVEL_BITMASK);
		e.ondragstart = function(e) {
			e.preventDefault();
		}
		e.className = "bitmask";
		e.innerText = "0x" + bitmask(top, bottom).toString(16);
	}

	function setupFieldValueEntry(top, bottom, field) {
		let e = maker.addBox(top, bottom, LEVEL_VALUE);
		e.className = "field-value";
		let fieldValue = (value & bitmask(top, bottom)) >>> bottom;
		e.innerHTML = "0x" + fieldValue.toString(16);
		if (field != null) {
			for (i in field.descriptions) {
				if (field.descriptions[i].equals == fieldValue) {
					e.innerHTML += "<span class='field-value-desc'>" + field.descriptions[i].value + "</span>";
					break;
				}
			}
		}
	}

	for (let i = reg.size - 1; i >= 0; i--) {
		let e = maker.addBit(i);
		e.className = "bit";
		e.innerText = String(i);
	}

	for (let i = reg.size - 1; i >= 0; i--) {
		let e = maker.addBox(i, i, LEVEL_CHECKBOXES);

		var chk = document.createElement("input");
		chk.type = "checkbox";
		chk.checked = (value & (1 << i)) != 0;
		// Make the entire box clickable, not just checkbox
		e.onclick = function() {
			this.bit = i;
			flipBit(this.bit);
		}
		e.appendChild(chk);
	}

	let lastPos = reg.size - 1;
	for (let i = 0; i < reg.fields.length; i++) {
		let field = reg.fields[i];
		if (field.top > reg.size) continue;
		// Insert reserved blank entries
		if (lastPos > field.top) {
			setupBitMaskEntry(lastPos, field.top + 1);
			maker.addBox(lastPos, field.top + 1, LEVEL_NAME);
			setupFieldValueEntry(lastPos, field.top + 1, null);
			i--;
			lastPos = field.bottom - 1;
			continue;
		}

		setupBitMaskEntry(field.top, field.bottom);

		let e = maker.addBox(field.top, field.bottom, LEVEL_NAME);
		e.className = "field-name";
		e.innerHTML = field.name;

		let desc = null;

		setupFieldValueEntry(field.top, field.bottom, field);

		lastPos = field.bottom - 1;
	}
	return maker.tbl;
}

function flipBit(b) {
	let n = Number(document.querySelector("#reg-value").value);
	n ^= (1 << b);
	document.querySelector("#reg-value").value = "0x" + n.toString(16);
	update();
}

function populateExamples() {
	for (let i = 0; i < examples.length; i++) {
		let reg = parseLanguage(examples[i]);
		let s = document.createElement("option");
		s.innerText = reg.name;
		document.querySelector("#examples").appendChild(s);
	}
	document.querySelector("#examples").onchange = function(e) {
		document.querySelector("#lang").value = examples[this.selectedIndex];
		update();
	}
}
populateExamples();

document.querySelector("#lang").value = examples[0];
document.querySelector("#reg-value").value = "0x11";
document.querySelector("#table-orientation").checked = false;
function update() {
	if (document.querySelector("#bitbox").children.length != 0) {
		document.querySelector("#bitbox").children[0].remove();
	}

	try {
		let reg = parseLanguage(document.querySelector("#lang").value);

		let isVertical = document.querySelector("#table-orientation").checked;
		if (isVertical) {
			document.querySelector("#app").className = "app-vertical";
		} else {
			document.querySelector("#app").className = "app";
		}
		let maker = isVertical ? VerticalTableMaker() : HorizontalTableMaker();
		let val = Number(document.querySelector("#reg-value").value);
		if (isNaN(val)) {
			throw "NaN";
		}
		let table = createTable(reg, val, maker);
		document.querySelector("#bitbox").appendChild(table);
	} catch(e) {
		document.querySelector("#bitbox").innerHTML = "<h3>" + e.toString() + "</h3>";
	}
}
document.querySelector("#table-orientation").onchange = update;
document.querySelector("#reg-value").oninput = update;
document.querySelector("#lang").oninput = update;
update();

// TODO: save url with
// history.pushState({}, null, "https://ret.futo.org/bitbash/?asdasd");
