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
	/// @brief Clear and reset buffer
	void (*clear)(struct OutBuffer *);
	/// @brief Append string or binary data. If string, len can be 0.
	void (*append)(struct OutBuffer *, const void *buf, unsigned int len);
};

int re_assemble(enum Arch arch, unsigned int base_addr, struct OutBuffer *buf, struct OutBuffer *err_buf, const char *input);

struct OutBuffer create_mem_buffer(unsigned int size);
struct OutBuffer create_mem_string_buffer(unsigned int size);
struct OutBuffer create_mem_hex_buffer(unsigned int size);
struct OutBuffer create_stdout_hex_buffer();
struct OutBuffer create_stdout_buffer();
const void *get_buffer_contents(struct OutBuffer *buf);

int parser_to_buf(const char *input, struct OutBuffer *buf, int options);
