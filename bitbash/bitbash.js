var tcrel3reg = {
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
	var reg = {
		"size": 32,
		"fields": []
	};

	function findField(name) {
		for (let i in reg.fields) {
			if (reg.fields[i].name == name) return reg.fields[i];
		}
		throw "Didn't find field '" + name + "'";
	}
	
	var split = code.split("\n");
	var reg_name = /name (.+)/;
	var reg_size = /size (.+)/;
	var set_bitfield_name = /\[([0-9]+):([0-9]+)\] = (.+)/;
	var set_bitfield_name_bit = /\[([0-9]+)\] = (.+)/;
	var case_bitfield_value = /if (.+) == ([xb0-9a-zA-Z]+): "(.+)"/;
	for (let i = 0; i < split.length; i++) {
		var match = split[i].match(set_bitfield_name);
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
		//throw "Error on line: '" + split[i] + "'";
		//console.log(match);
	}

	return reg;
}

function HorizontalTableMaker() {
	return {
		tbl: document.createElement("table"),
		bits: document.createElement("tr"),
		fields: document.createElement("tr"),
		fieldsBitMasks: document.createElement("tr"),
		init: function(size) {
			this.tbl.appendChild(this.bits);
			this.tbl.appendChild(this.fields);
			this.tbl.appendChild(this.fieldsBitMasks);
			this.tbl.width = "100%";
			this.tbl.setAttribute("cellspacing", "0");
			this.tbl.setAttribute("cellpadding", "4");
		},
		addBit: function(bit) {
			var th = document.createElement("th");
			this.bits.appendChild(th);
			return th;
		},
		addField: function(top, bottom) {
			var th = document.createElement("th");
			th.colSpan = top - bottom + 1;
			this.fields.appendChild(th);
			return th;
		},
		addFieldBitMask: function(top, bottom) {
			var th = document.createElement("th");
			th.colSpan = top - bottom + 1;
			this.fieldsBitMasks.appendChild(th);
			return th;
		},
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
			var tr = document.createElement("tr");
			this.tbl.appendChild(tr);
			var th = document.createElement("th");
			tr.appendChild(th);
			return th;
		},
		addField: function(top, bottom) {
			var th = document.createElement("th");
			th.rowSpan = top - bottom + 1;
			this.tbl.children[this.tbl.children.length - top - 1].appendChild(th);
			return th;
		},
		addFieldBitMask: function(top, bottom) {
			return this.addField(top, bottom);
		}
	};
}

function createTable(reg, value, maker) {
	maker.init(reg.size);
	reg.fields.sort((a, b) => b.top - a.top);

	function setupBitMaskEntry(e, top, bottom) {
		e.className = "bitfield";
		e.innerText = "0x" + bitmask(top, bottom).toString(16);
	}

	for (let i = reg.size - 1; i >= 0; i--) {
		var e = maker.addBit(i);
		if ((value & (1 << i)) != 0) {
			e.className = "bit-high";
		} else {
			e.className = "bit-low";
		}
		e.innerText = String(i);
	}

	let lastPos = reg.size - 1;
	for (let i = 0; i < reg.fields.length; i++) {
		let field = reg.fields[i];
		if (field.top > reg.size) continue;
		// Insert reserved blank entries
		if (lastPos > field.top) {
			let e = maker.addField(lastPos, field.top + 1);
			setupBitMaskEntry(maker.addFieldBitMask(lastPos, field.top + 1), lastPos, field.top + 1);
			i--;
			lastPos = field.bottom - 1;
			continue;
		}
		let e = maker.addField(field.top, field.bottom);

		let fieldValue = (value & bitmask(field.top, field.bottom)) >>> field.bottom;

		e.innerHTML = field.name + "<br>" + "0x" + fieldValue.toString(16);		

		setupBitMaskEntry(maker.addFieldBitMask(field.top, field.bottom), field.top, field.bottom);

		lastPos = field.bottom - 1;
	}
	return maker.tbl;
}

document.querySelector("#lang").value = `
name REGISTER
size 32
[31] = RESET
[5:1] = INDEX
if INDEX == 0b00: "Mode A"
if INDEX == 0b01: "Mode B"
[0:0] = ENABLE
[9:8] = INTR
`.trim();
document.querySelector("#reg-value").value = "0x80000000";
function update() {
	if (document.querySelector("#bitbox").children.length != 0) {
		document.querySelector("#bitbox").children[0].remove();
	}

	try {
		let reg = parseLanguage(document.querySelector("#lang").value);

		var isVertical = document.querySelector("#table-orientation").checked;
		if (isVertical) {
			document.querySelector("#bitbox").className = "bitbox-vertical";
		} else {
			document.querySelector("#bitbox").className = "";
		}
		var maker = isVertical ? VerticalTableMaker() : HorizontalTableMaker();
		var val = Number(document.querySelector("#reg-value").value);
		var table = createTable(reg, val, maker);
		document.querySelector("#bitbox").appendChild(table);
	} catch(e) {
		document.querySelector("#bitbox").innerHTML = "<h3>" + e.toString() + "</h3>";
	}
}
document.querySelector("#table-orientation").onchange = update;
document.querySelector("#reg-value").oninput = update;
document.querySelector("#lang").oninput = update;
update();
