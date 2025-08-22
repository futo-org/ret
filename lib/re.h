#pragma once
#include <stdint.h>
#include <stdarg.h>

enum Arch {
	ARCH_ARM64 = 0,
	ARCH_ARM32 = 1,
	ARCH_X86 = 2,
	ARCH_X86_64 = 3,
	ARCH_RISCV32 = 4,
	ARCH_RISCV64 = 5,
	ARCH_WASM = 6,
	ARCH_ARM32_THUMB = 7,
	ARCH_POWERPC = 7,
};

enum ParseOptions {
	PARSE_AS_U8 = 1 << 0,
	PARSE_AS_U16 = 1 << 1,
	PARSE_AS_U32 = 1 << 2,
	PARSE_AS_U64 = 1 << 3,
	PARSE_AS_AUTO = 1 << 4,

	// TODO: Skip X numbers at the beginning of a line
	SKIP_1_AT_START = 1 << 5,
	SKIP_2_AT_START = 1 << 6,

	// TODO:
	PARSE_AS_BASE_10 = 1 << 10,
	// TODO:
	PARSE_AS_BIG_ENDIAN = 1 << 11,

	// Parse // comments in the hex code, same as C does
	PARSE_C_COMMENTS = 1 << 12,
};

enum OutputOptions {
	// If the parser was piped into a buffer the data format will be detected
	// automatically
	OUTPUT_AS_AUTO = 0,
	OUTPUT_AS_U8 = 1 << 1,
	OUTPUT_AS_U16 = 1 << 2,
	OUTPUT_AS_U32 = 1 << 3,
	OUTPUT_AS_U64 = 1 << 4,
	OUTPUT_AS_U32_BINARY = 1 << 5,
	OUTPUT_AS_U8_BINARY = 1 << 6,
	OUTPUT_AS_C_ARRAY = 1 << 10,
	OUTPUT_AS_RUST_ARRAY = 1 << 11,
	// TODO:
	OUTPUT_AS_BIG_ENDIAN = 1 << 12,
	// Split output every 4 bytes
	OUTPUT_SPLIT_BY_FOUR = 1 << 13,
	// Split byte output by each instruction
	OUTPUT_SPLIT_BY_INSTRUCTION = 1 << 14,
	// Output assembly instructions beside the hex in C comments
	OUTPUT_ASSEMBLY_ANNOTATIONS = 1 << 15,
};

enum AssemblyOptions {
	// Intel is the default syntax for assembler and disassembler
	RET_SYNTAX_INTEL = 0,
	RET_SYNTAX_ATT = 1 << 1,
	RET_SYNTAX_NASM = 1 << 2,
	RET_SYNTAX_MASM = 1 << 3,
	RET_SYNTAX_GAS = 1 << 4,

	// Tries to disassemble from every valid offset.
	// If not chosen, .byte or .db directives will be added for the rest of the program.
	RET_AGGRESSIVE_DISASM = 1 << 10,
};

struct RetBuffer {
	/// @brief Growable buffer that holds string or binary data
	char *buffer;
	/// @brief Current length of valid data in the buffer
	unsigned int offset;
	/// @brief Size of allocated buffer
	unsigned int length;
	/// @brief optional counter used for newline breaks
	int counter;
	/// @brief Output options used by some append functions, OUTPUT_AS_AUTO by default
	int output_options;
	/// @brief Clear and reset buffer
	void (*clear)(struct RetBuffer *);
	/// @brief Append string or binary data. If len is 0, then buf is treated like a NULL terminated string.
	void (*append)(struct RetBuffer *, const void *buf, unsigned int len);

	struct RetBuffer *mirror1;
	struct RetBuffer *mirror2;
};

/// @brief Buffer that writes into memory buffer
struct RetBuffer create_mem_buffer(void);
/// @brief Buffer that prints into a string buffer
struct RetBuffer create_mem_string_buffer(void);
/// @brief Buffer that prints raw data into a hex stream
struct RetBuffer create_mem_hex_buffer(void);
/// @brief Buffer that prints hex characters to stdout
struct RetBuffer create_stdout_hex_buffer(void);
/// @brief Buffer that prints directly to stdout
struct RetBuffer create_stdout_buffer(void);
/// @brief Buffer that pipes into two buffers
struct RetBuffer create_mirror_buffer(struct RetBuffer *buf1, struct RetBuffer *buf2);

/// @brief Get pointer to buffer contents
const void *buffer_get_contents(struct RetBuffer *buf);
/// @brief Appends string to buffer (passes length 0)
void buffer_appendf(struct RetBuffer *buf, const char *fmt, ...);
/// @brief Append data to the buffer with a specific output mode
void buffer_append_mode(struct RetBuffer *buf, const void *data, unsigned int length, int output_options);

/// @brief Run the hex parser and output into a buffer
int parser_to_buf(const char *input, struct RetBuffer *buf, int parse_options, int output_options);

int test_buffer(void);

int re_emulator(enum Arch arch, unsigned int base_addr, struct RetBuffer *asm_buffer, struct RetBuffer *log);

inline static int write_u8(void *buf, uint8_t out) {
	((uint8_t *)buf)[0] = out;
	return 1;
}
inline static int write_u16(void *buf, uint16_t out) {
	uint8_t *b = (uint8_t *)buf;
	b[0] = out & 0xFF;
	b[1] = (out >> 8) & 0xFF;
	return 2;
}
inline static int write_u32(void *buf, uint32_t out) {
	uint8_t *b = (uint8_t *)buf;
	b[0] = out & 0xFF;
	b[1] = (out >> 8) & 0xFF;
	b[2] = (out >> 16) & 0xFF;
	b[3] = (out >> 24) & 0xFF;
	return 4;
}
inline static int read_u8(const void *buf, uint8_t *out) {
	const uint8_t *b = (const uint8_t *)buf;
	*out = b[0];
	return 1;
}
inline static int read_u16(const void *buf, uint16_t *out) {
	const uint8_t *b = (const uint8_t *)buf;
	*out = (uint16_t)b[0] | ((uint16_t)b[1] << 8);
	return 2;
}
inline static int read_u32(const void *buf, uint32_t *out) {
	const uint8_t *b = (const uint8_t *)buf;
	*out = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
	return 4;
}
