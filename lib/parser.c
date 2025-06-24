// A smart hex parser, should be able to parse hex text in as many weird formats as possible.
#include <stdio.h>
#include "re.h"

struct HexPars {
	uint32_t options;

	const char *buf;
	int of;

	int parsing_long_hex;
};


struct Number {
	uint64_t n;
	int n_of_chars;
	int data_type_size;
	int too_long;
	int eof;
};

/*
TODO: How to parse this?
- Parse as u16
- Skip first number on each line
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
	// Handle single digits, double, and triple (0ab, 021, and 0xff since 'x' gets skipped)
	case 1:
	case 2:
		return 1;
	// u16 should be 4 chars
	case 3:
	case 4:
		return 2;
	case 8:
		return 4;
	case 16:
		return 8;
	// Otherwise, it's safe to consider it a u32.
	default:
		return 4;
	}
}

// Parse a number at current position
struct Number lex_number(struct HexPars *p) {
	struct Number n = {0};
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

		if (n_of_chars >= 2 && (p->options & PARSE_AS_U8)) {
			n.data_type_size = 1;
			break;
		} else if (n_of_chars >= 4 && (p->options & PARSE_AS_U16)) {
			n.data_type_size = 2;
			break;
		} else if (n_of_chars >= 8 && (p->options & PARSE_AS_U32)) {
			n.data_type_size = 4;
			break;
		} else if (n_of_chars >= 16 && (p->options & PARSE_AS_U32)) {
			n.data_type_size = 8;
			break;
		} else if (n_of_chars > 16) {
			// In this case, we are PARSE_AS_AUTO
			// Reset to let caller handle longer sequences
			p->parsing_long_hex = 1;
			p->of = starting_of;
			return n;
		}
	}

	if (p->options & PARSE_AS_AUTO) {
		n.data_type_size = guess_data_type(n_of_chars);
	}

	n.n = w;
	n.n_of_chars = n_of_chars;
	p->of = of;
	return n;
}

void create_parser(struct HexPars *p, const char *in, int options) {
	p->options = PARSE_AS_AUTO;
	p->buf = in;
	p->parsing_long_hex = 0;
	p->of = 0;
}

struct Number parser_next(struct HexPars *p) {
	const char *in = p->buf;

	struct Number eof = {0};
	eof.eof = 1;

	while (1) {
		if (in[p->of] == '\0') {
			return eof;
		}
	
		// Always parse as hex if '0x' is found
		// TODO: Check buf+2
		if (in[p->of] == '0' && in[p->of + 1] == 'x') {
			p->of += 2;
			// TODO: Check if following is valid hex, may not be
		}
		if (is_digit(in[p->of]) || is_hexa(in[p->of])) {
			struct Number n = lex_number(p);
			// Assume long sequences are a u8 stream
			if (p->parsing_long_hex) {
				p->options |= PARSE_AS_U8;
				p->parsing_long_hex = 0;
				continue;
			}
			return n;
		} else {
			p->of++;
		}
	}
}

int parser_to_buf(const char *input, struct RetBuffer *buf, int parse_options, int output_options) {
	buf->clear(buf);
	struct HexPars p;
	create_parser(&p, input, parse_options);

	int old_opt = buf->output_options;
	buf->output_options = output_options;

	// Write numbers into buffer first before outputting in the case that u8
	// needs to be transformed into u32 or u64
	uint8_t buffer[64];
	unsigned int of = 0;
	while (1) {
		struct Number n = parser_next(&p);
		if (buf->output_options == OUTPUT_AS_AUTO) {
			if (n.data_type_size == 4) buf->output_options = OUTPUT_AS_U32;
			if (n.data_type_size == 2) buf->output_options = OUTPUT_AS_U16;
			if (n.data_type_size == 1) buf->output_options = OUTPUT_AS_U8;
		}
		if (of + 4 >= sizeof(buffer)) {
			buf->append(buf, buffer, of);
			of = 0;
		}
		if (!n.eof) {
			if (n.data_type_size == 4) of += write_u32(buffer + of, n.n);
			if (n.data_type_size == 2) of += write_u16(buffer + of, n.n);
			if (n.data_type_size == 1) of += write_u8(buffer + of, n.n);
		} else {
			break;
		}
	}

	if (of > 0) {
		buf->append(buf, buffer, of);
	}

	buf->output_options = old_opt;

	return 0;
}
	
