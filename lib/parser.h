#include <stdint.h>
#pragma once

enum Types {
	PARSE_AS_U8 = 1 << 0,
	PARSE_AS_U16 = 1 << 1,
	PARSE_AS_U32 = 1 << 2,
	PARSE_AS_U64 = 1 << 3,
	PARSE_AS_SMART = 1 << 4,

	// Skip X numbers at the beginning of a line
	SKIP_1_AT_START = 1 << 5,
	SKIP_2_AT_START = 1 << 6,

	PARSE_AS_BASE_10 = 1 << 10,
};

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

void create_parser(struct HexPars *p, const char *in, int options);
struct Number parser_next(struct HexPars *p);
