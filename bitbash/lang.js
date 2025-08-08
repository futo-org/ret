// Traditional lexer
function isAlpha(c) {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c === '_';
}

function isDigit(c) {
	return c >= '0' && c <= '9';
}

function isHexDigit(c) {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

function isBinDigit(c) {
	return c === '0' || c === '1';
}

function isWhitespace(c) {
	return c === ' ' || c === '\t' || c === '\n' || c === '\r';
}

class Parser {
	constructor(str) {
		this.str = str;
		this.off = 0;
	}

	nextTok() {
		let str = this.str;
		while (this.off < str.length) {
			let c = str[this.off];

			if (isWhitespace(c)) {
				this.off++;
				continue;
			} else if (c === '"') {
				this.off++;
				let start = this.off;
				while (this.off < str.length && str[this.off] !== '"') this.off++;
				this.off++;
				return {
					type: "str",
					value: str.slice(start, this.off)
				};
			} else if (c === '[') {
				this.off++;
				let top = 0;
				let bottom = 0;
				let start = this.off;
				while (this.off < str.length && str[this.off] !== ']' && str[this.off] !== ':') this.off++;
				if (str[this.off] === ':') {
					top = Number(str.slice(start, this.off));
					this.off++;
					start = this.off;
					while (this.off < str.length && str[this.off] !== ']') this.off++;
					bottom = Number(str.slice(start, this.off));
				} else {
					top = Number(str.slice(start, this.off));
					bottom = top;
				}
				this.off++;
				return {
					type: "bit",
					top: top,
					bottom: bottom
				};
			} else {
				let start = this.off;
				while (this.off < str.length && !isWhitespace(str[this.off]) && str[this.off] !== ':') {
					this.off++;
				}
				return {
					type: "text",
					value: str.slice(start, this.off)
				};
			}
		}

		return {
			type: "eof",
		};
	}

	parse() {
		let reg = {
			"size": 32,
			"fields": []
		};
		while (true) {
			let tok = this.nextTok();
			console.log(tok);
			if (tok.type === "text") {
				tok = this.nextTok();
				reg.name = tok.value;
			} else if (tok.type == "eof") {
				break;
			} else {
				break;
			}
		}

		return reg;
	}
};
