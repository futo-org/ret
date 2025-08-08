function bitmask(hi, lo) {
	let w = BigInt(hi - lo + 1);
	return ((1n << w) - 1n) << BigInt(lo);
}

function parseLanguage(code, value) {
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

	let conditions = [true];
	
	let split = code.split("\n");
	let reg_name = /name (.+)/;
	let reg_size = /size (.+)/;
	let set_bitfield_name = /\[([0-9]+):([0-9]+)\] = (.+)/;
	let set_bitfield_name_bit = /\[([0-9]+)\] = (.+)/;
	let case_bitfield_value = /if (.+) == ([xb0-9a-zA-Z]+): "(.+)"/;
	let case_bitfield_block = /if (.+) == ([xb0-9a-zA-Z]+) {/;
	//let case_bits_block = /if \[([0-9]+):([0-9]+)\] == ([xb0-9a-zA-Z]+) {/;
	let end_block = /}$/;
	let end_else_block = /} else {$/;
	for (let i = 0; i < split.length; i++) {
		if (split[i].startsWith("//")) continue;
		let match = split[i].match(set_bitfield_name);
		if (match) {
			if (Number(match[2]) > Number(match[1])) {
				throw "Incorrect bit format. Must be high:low. For example [5:0]."
			}
			let fieldValue = (BigInt(value) & bitmask(Number(match[1]), Number(match[2]))) >> BigInt(Number(match[2]));
			if (conditions.at(-1) == false) continue;
			reg.fields.push({
				"name": match[3],
				"top": Number(match[1]),
				"bottom": Number(match[2]),
				"fieldValue": fieldValue,
				"description": "",
			});
			continue;
		}
		match = split[i].match(set_bitfield_name_bit);
		if (match) {
			if (conditions.at(-1) == false) continue;
			let fieldValue = (BigInt(value) & bitmask(Number(match[1]), Number(match[1]))) >> BigInt(Number(match[1]));
			reg.fields.push({
				"name": match[2],
				"top": Number(match[1]),
				"bottom": Number(match[1]),
				"fieldValue": fieldValue,
				"description": "",
			});
			continue;
		}
		match = split[i].match(case_bitfield_value);
		if (match) {
			if (conditions.at(-1) == false) continue;
			let field = findField(match[1]);
			if (field.fieldValue == Number(match[2])) {
				field.description = match[3];
			}
			continue;
		}
		match = split[i].match(case_bitfield_block);
		if (match) {
			if (conditions.at(-1) == false) {
				conditions.push(false);
			} else {
				conditions.push(findField(match[1]).fieldValue == Number(match[2]));
			}
			continue;
		}
		match = split[i].match(end_block);
		if (match) {
			conditions.pop();
			if (conditions.length == 0) {
				throw "Misplaced brace";
			}
			continue;
		}
		match = split[i].match(end_else_block);
		if (match) {
			conditions.push(!conditions.pop());
			continue;
		}
		match = split[i].match(reg_size);
		if (match) {
			if (conditions.at(-1) == false) continue;
			reg.size = Number(match[1]);
			if (reg.size > 512) {
				throw "Unsupported register size";
			}
			continue;
		}
		match = split[i].match(reg_name);
		if (match) {
			if (conditions.at(-1) == false) continue;
			reg.name = match[1];
			continue;
		}
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
			th.innerText = "";
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
		let fieldValue = (BigInt(value) & bitmask(top, bottom)) >> BigInt(bottom);
		e.innerHTML = "0x" + fieldValue.toString(16);
		if (field != null) {
			e.innerHTML += "<span class='field-value-desc'>" + field.description + "</span>";
		}
	}

	for (let i = reg.size - 1; i >= 0; i--) {
		let e = maker.addBit(i);
		e.className = "bit";
		e.innerText = String(i);
	}

	for (let i = reg.size - 1; i >= 0; i--) {
		let e = maker.addBox(i, i, LEVEL_CHECKBOXES);
		e.className = "bit-checkbox";

		let chk = document.createElement("input");
		chk.type = "checkbox";
		chk.checked = (BigInt(value) & (1n << BigInt(i))) != 0n;
		chk.id = "checkbox_" + String(i);
		// Make the entire box clickable, not just checkbox
		e.onclick = function() {
			this.bit = i;
			flipBit(this.bit);
		}
		e.ondragstart = function(e) {
			e.preventDefault();
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
	n = BigInt(n) ^ (1n << BigInt(b));
	document.querySelector("#reg-value").value = "0x" + n.toString(16);
	update();
}

function populateExamples() {
	for (let i = 0; i < examples.length; i++) {
		let reg = parseLanguage(examples[i], 0x0);
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

let urlOptions = Object.fromEntries(new URLSearchParams(window.location.search).entries());
if (urlOptions.hasOwnProperty("text")) {
	document.querySelector("#lang").value = decodeURIComponent(urlOptions.text);
} else {
	document.querySelector("#lang").value = examples[0];
}
if (urlOptions.hasOwnProperty("regValue")) {
	document.querySelector("#reg-value").value = urlOptions.regValue;
} else {
	document.querySelector("#reg-value").value = "0x11";
}
if (urlOptions.hasOwnProperty("orientation")) {
	document.querySelector("#table-orientation").checked = urlOptions.orientation === "true";
} else {
	document.querySelector("#table-orientation").checked = false;
}

document.querySelector("#save-state").onclick = function() {
	urlOptions.text = encodeURIComponent(document.querySelector("#lang").value);
	urlOptions.orientation = String(document.querySelector("#table-orientation").checked);
	urlOptions.regValue = String(document.querySelector("#reg-value").value);

	let newUrl = window.location.origin + window.location.pathname + "?" + new URLSearchParams(urlOptions).toString();
	history.pushState({}, null, newUrl);
}

function update() {
	if (document.querySelector("#bitbox").children.length != 0) {
		document.querySelector("#bitbox").children[0].remove();
	}

	try {
		let val = Number(document.querySelector("#reg-value").value);
		let reg = parseLanguage(document.querySelector("#lang").value, val);

		let isVertical = document.querySelector("#table-orientation").checked;
		if (isVertical) {
			document.querySelector("#app").className = "app-vertical";
		} else {
			document.querySelector("#app").className = "app";
		}
		let maker = isVertical ? VerticalTableMaker() : HorizontalTableMaker();
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
