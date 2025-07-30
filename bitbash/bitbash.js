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

function parseLanguage(code) {
	var reg = {
		"size": 32,
		"fields": []
	};

	function findField(name) {
		for (let i in reg.fields) {
			if (reg.fields[i].name == name) return reg.fields[i];
		}
		throw "Didn't find field";
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
		}
		match = split[i].match(set_bitfield_name_bit);
		if (match) {
			reg.fields.push({
				"name": match[2],
				"top": Number(match[1]),
				"bottom": Number(match[1]),
				"descriptions": [],
			});
		}
		match = split[i].match(case_bitfield_value);
		if (match) {
			findField(match[1]).descriptions.push({
				"equals": Number(match[2]),
				"value": match[3],
			});
		}
		//console.log(match);
	}

	return reg;
}

const horizontalTableMaker = {
	create: function() {
		this.tbl = document.createElement("table");
		this.bits = document.createElement("tr");
		this.tbl.appendChild(this.bits);
		this.fields = document.createElement("tr");
		this.tbl.appendChild(this.fields);
		this.tbl.width = "100%";
	},
	addBit: function(bit) {
		var th = document.createElement("th");
		this.bits.appendChild(th);
		return th;
	},
	addField: function(top, bottom) {
		var th = document.createElement("th");
		this.tbl.appendChild(th);
		return th;
	}
};

function createTable(reg, value) {
	let maker = horizontalTableMaker;
	maker.create();
	reg.fields.sort((a, b) => b.top - a.top);

	for (let i = reg.size - 1; i >= 0; i--) {
		var e = maker.addBit(i);
		if ((value & (1 << i)) != 0) {
			e.className = "bit-high";
		}
		e.innerText = String(i);
	}

	var lastPos = reg.size - 1;
	for (let i = 0; i < reg.fields.length; i++) {
		var field = reg.fields[i];
		var e = maker.addField(field.top, field.bottom);
		// Insert reserved blank entries
		if (lastPos > field.top) {
			e.colSpan = lastPos - field.top
			i--;
			lastPos = field.bottom - 1;
			continue;
		}
		e.colSpan = field.top - field.bottom + 1;
		e.innerText = field.name;
		lastPos = field.bottom - 1;
	}
	return maker.tbl;
}

document.querySelector("#lang").value = `
name REGISTER
size 32
[31] = RESET
[5:1] = INDEX
[0:0] = ENABLE
[9:8] = INTR
if INDEX == 0b00: "Mode A"
if INDEX == 0b01: "Mode B"
`.trim();
function update() {
	let reg = parseLanguage(document.querySelector("#lang").value);
	// console.log(reg);
	if (document.querySelector("#bitbox").children.length != 0) {
		document.querySelector("#bitbox").children[0].remove();
	}
	document.querySelector("#bitbox").appendChild(createTable(reg, 0x80000000));
}
document.querySelector("#lang").oninput = update;
update();
