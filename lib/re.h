#pragma once
#include <stdint.h>

enum Arch {
	ARCH_ARM64 = 0,
	ARCH_ARM32 = 1,
	ARCH_X86 = 2,
	ARCH_X86_64 = 3,
	ARCH_RISCV32 = 4,
	ARCH_RISCV64 = 5,
	ARCH_WASM = 6,
	ARCH_ARM32_THUMB = 7,
};

enum ParseOptions {
	PARSE_AS_U8 = 1 << 0,
	PARSE_AS_U16 = 1 << 1,
	PARSE_AS_U32 = 1 << 2,
	PARSE_AS_U64 = 1 << 3,
	PARSE_AS_AUTO = 1 << 4,

	// Skip X numbers at the beginning of a line
	SKIP_1_AT_START = 1 << 5,
	SKIP_2_AT_START = 1 << 6,

	PARSE_AS_BASE_10 = 1 << 10,
};

enum OutputOptions {
	OUTPUT_AS_AUTO = 0,
	OUTPUT_AS_U8 = 1 << 1,
	OUTPUT_AS_U16 = 1 << 2,
	OUTPUT_AS_U32 = 1 << 3,
	OUTPUT_AS_U64 = 1 << 4,
	OUTPUT_AS_C_ARRAY = 1 << 10,
	OUTPUT_AS_RUST_ARRAY = 1 << 11,
};

struct ReTool {
	enum Arch arch;
};

struct OutBuffer {
	/// @brief Growable buffer that holds string or binary data
	char *buffer;
	/// @brief Current length of valid data in the buffer
	unsigned int offset;
	/// @brief Size of allocated buffer
	unsigned int length;
	// optional counter used for newline breaks
	int counter;
	// Output options used by some append functions
	int output_options;
	/// @brief Clear and reset buffer
	void (*clear)(struct OutBuffer *);
	/// @brief Append string or binary data. If string, len can be 0.
	void (*append)(struct OutBuffer *, const void *buf, unsigned int len);
};

int re_assemble(enum Arch arch, unsigned int base_addr, struct OutBuffer *buf, struct OutBuffer *err_buf, const char *input);

struct OutBuffer create_mem_buffer(void);
struct OutBuffer create_mem_string_buffer(void);
struct OutBuffer create_mem_hex_buffer(void);
struct OutBuffer create_stdout_hex_buffer(void);
struct OutBuffer create_stdout_buffer(void);
const void *get_buffer_contents(struct OutBuffer *buf);

int parser_to_buf(const char *input, struct OutBuffer *buf, int parse_options, int output_options);
