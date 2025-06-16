#include <stdint.h>
#pragma once

enum Types {
	PARSE_AS_U8 = 0,
	PARSE_AS_U16 = 1,
	PARSE_AS_U32 = 2,
	PARSE_AS_U64 = 3,
	PARSE_AS_SMART = 4,
};

struct HexPars {
	// How many numbers to ignore at the start of every line
	int skip_numbers;
	// How to handle the lengths of numbers
	enum Types parse_as;
	int parse_as_base10;

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
