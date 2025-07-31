let tcrel3reg = {
	"reg": "TCR_EL3",
	"size": 64,
	"fields": [
		{
			"top": 5,
			"bottom": 0,
			"name": "T0SZ",
			"descriptions": [
				{"equals": 0, "value": "Normal memory, Inner Non-cacheable."},
				{"equals": 1, "value": "Normal memory, Inner Write-Back Read-Allocate Write-Allocate Cacheable."}
			]
		}
	]
}

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
		if (match.startsWith("//")) continue;
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
			this.tbl.setAttribute("cellspacing", "0");
			this.tbl.setAttribute("cellpadding", "4");
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

	//var resCounter = 0;

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

	function setupFieldValueEntry(top, bottom) {
		let e = maker.addBox(top, bottom, LEVEL_VALUE);
		e.className = "field-value";
		let fieldValue = (value & bitmask(top, bottom)) >>> bottom;
		e.innerHTML = "0x" + fieldValue.toString(16);
	}

	for (let i = reg.size - 1; i >= 0; i--) {
		let e = maker.addBit(i);
		if ((value & (1 << i)) != 0) {
			e.className = "bit-high";
		} else {
			e.className = "bit-low";
		}
		e.innerText = String(i);
	}

	// for (let i = reg.size - 1; i >= 0; i--) {
	// 	let e = maker.addBox(i, i, LEVEL_CHECKBOXES);
	// 	e.innerHTML = "<input type='checkbox'>";
	// }

	let lastPos = reg.size - 1;
	for (let i = 0; i < reg.fields.length; i++) {
		let field = reg.fields[i];
		if (field.top > reg.size) continue;
		// Insert reserved blank entries
		if (lastPos > field.top) {
			setupBitMaskEntry(lastPos, field.top + 1);
			let e = maker.addBox(lastPos, field.top + 1, LEVEL_NAME);
			//e.innerText = "RES" + resCounter++;
			setupFieldValueEntry(lastPos, field.top + 1);
			i--;
			lastPos = field.bottom - 1;
			continue;
		}

		setupBitMaskEntry(field.top, field.bottom);

		let e = maker.addBox(field.top, field.bottom, LEVEL_NAME);
		e.className = "field-name";
		e.innerHTML = field.name;

		setupFieldValueEntry(field.top, field.bottom);

		lastPos = field.bottom - 1;
	}
	return maker.tbl;
}

document.querySelector("#lang").value = `
name CR0
size 32
[31] = PG
[30] = CD
[29] = NW
[16] = WP
[5] = NE
[4] = ET
[3] = TS
[2] = EM
[1] = MP
[0] = PE
`.trim();
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
			document.querySelector("#bitbox").className = "bitbox-vertical";
		} else {
			document.querySelector("#bitbox").className = "";
		}
		let maker = isVertical ? VerticalTableMaker() : HorizontalTableMaker();
		let val = Number(document.querySelector("#reg-value").value);
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
