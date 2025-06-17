// A smart hex parser, should be able to intelligently parse hex text output from any program. 
#include <stdio.h>
#include "re.h"
#include "parser.h"

/*
Options
- Parse as a sequence of:
  - U8
  - U16
  - U32
  - U64
  - Clever (mixed)
- Parse as base10?

Parse sequence of 3 bytes as u8:
03f 0df -> 3f df

Parse sequence of 4 bytes as u16: 
00f1 66 -> f1 00 66

Parse sequence of any longer as u32:
00001 12345678 -> 01 00 00 00 78 56 34 12

If '0x' is found, parse as hex always:
0x123 0x123 0x123 -> 7b 7b 7b

0000000 2023 7243 736f 2d73 6f63 706d 6c69 7461
0000010 6f69 206e 7473 6275 2073 6f66 2072 4e47
0000020 2055 616d 656b 230a 7720 203a 6957 646e
0000030 776f 0a73 2023 3a6c 4c20 6e69 7875 230a
0000040 6d20 203a 614d 0a63 6568 706c 0a3a 4009
0000050 6365 6f68 2220 6176 696c 2064 6176 756c
0000060 7365 6620 726f 5420 5241 4547 3a54 7720
0000070 202c 2c6c 6d20 0a22 690a 6e66 6564 2066
0000080 4154 4752 5445 240a 7728 7261 696e 676e
0000090 5420 5241 4547 2054 6f6e 2074 6564 6966
00000a0 656e 2c64 6120 7373 6d75 6e69 2067 694c
00000b0 756e 2978 540a 5241 4547 2054 3d3a 6c20
00000c0 650a 646e 6669 0a0a 5241 4843 3a20 203d
00000d0 3878 5f36 3436 0a0a 6669 7165 2820 2824
00000e0 4154 4752 5445 2c29 2977 4d0a 4e49 5747
00000f0 3a20 203d 3878 5f36 3436 772d 3436 6d2d
0000100 6e69 7767 3233 430a 2043 3d3a 2420 4d28
*/

static int is_digit(char c) {
	return c >= '0' && c <= '9';
}
static int is_hexa(char c) {
	return (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int guess_data_type(int n_of_chars) {
	switch (n_of_chars) {
	// Handle single digits, double, and triple (0ab, 021)
	case 1:
	case 2:
	case 3:
		return 1;
	// u16 should be 4 chars
	case 4:
		return 2;
	case 8:
		return 8;
	// Otherwise, it's safe to consider it a u32.
	default:
		return 4;
	}
}

// Parse a number at current position
struct Number lex_number(struct HexPars *p) {
	struct Number n;
	n.eof = 0;
	n.too_long = 0;
	uint64_t w = 0;
	int n_of_chars = 0;
	int starting_of = p->of;
	const char *in = p->buf;
	int of = p->of;
	while (1) {
		char c = in[of];
		if (c == '\0') {
			break;
		}
		if (is_digit(c)) {
			w *= 16;
			w += in[of] - '0';
		} else if (c >= 'A' && c <= 'F') {
			w *= 16;
			w += 10 + in[of] - 'A';
		} else if (c >= 'a' && c <= 'f') {
			w *= 16;
			w += 10 + in[of] - 'a';
		} else {
			break;
		}
		of++;
		n_of_chars++;

		if (n_of_chars >= 2 && p->parse_as == PARSE_AS_U8) {
			n.data_type_size = 1;
			break;
		} else if (n_of_chars >= 4 && p->parse_as == PARSE_AS_U16) {
			n.data_type_size = 2;
			break;
		} else if (n_of_chars >= 8 && p->parse_as == PARSE_AS_U32) {
			n.data_type_size = 4;
			break;
		} else if (n_of_chars >= 16 && p->parse_as == PARSE_AS_U32) {
			n.data_type_size = 8;
			break;
		} else if (n_of_chars > 16) {
			// Reset to let caller handle longer sequences
			p->parsing_long_hex = 1;
			p->of = starting_of;
			return n;
		}
	}

	if (p->parse_as == PARSE_AS_SMART) {
		n.data_type_size = guess_data_type(n_of_chars);
	}

	n.n = w;
	n.n_of_chars = n_of_chars;
	p->of = of;
	return n;
}

static int parse_as_to_size(enum Types as) {
	switch (as) {
	case PARSE_AS_U8:
	case PARSE_AS_SMART:
		return 1;
	case PARSE_AS_U16:
		return 2;
	case PARSE_AS_U32:
		return 4;
	case PARSE_AS_U64:
		return 8;
	}
}

void create_parser(struct HexPars *p, const char *in, int options) {
	p->parse_as = PARSE_AS_SMART;
	p->buf = in;
	p->parsing_long_hex = 0;
	p->of = 0;
}

struct Number parser_next(struct HexPars *p) {
	int is_hex = 1;
	uint64_t w = 0;
	int n_of_chars = 0;
	const char *in = p->buf;

	struct Number eof = {
		.eof = 1,
	};

	parsing_long_hex:;
	if (p->parsing_long_hex) {
		if (in[p->of] == '\0') return eof;
		if (is_digit(in[p->of]) || is_hexa(in[p->of])) {
			struct Number n = lex_number(p);
			return n;
		} else {
			p->parsing_long_hex = 0;
		}
	}

	while (1) {
		if (in[p->of] == '\0') {
			return eof;
		}
	
		int is_hex = 1;
		uint64_t w = 0;
		int n_of_chars = 0;

		// Always parse as hex if '0x' is found
		// TODO: Check buf+2
		if (in[p->of] == '0' && in[p->of + 1] == 'x') {
			p->of += 2;
			is_hex = 1;
			// TODO: Check if following is valid hex, may not me
		}
		if (is_digit(in[p->of]) || is_hexa(in[p->of])) {
			struct Number n = lex_number(p);
			if (p->parsing_long_hex) {
				goto parsing_long_hex;
			}
			return n;
		} else {
			p->of++;
		}
	}
}

int parser_to_buf(const char *input, struct OutBuffer *buf, int options) {
	buf->clear(buf);
	struct HexPars p;
	create_parser(&p, input, 0);

	while (1) {
		struct Number n = parser_next(&p);
		if (n.eof) break;
		buf->append(buf, &n.n, n.data_type_size);
	}

	return 0;
}
