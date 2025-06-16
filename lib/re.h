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
};

struct ReTool {
	enum Arch arch;
};

struct OutBuffer {
	void *handle;
	char *buffer;
	unsigned int offset;
	unsigned int length;
	int counter;
	void (*clear)(struct OutBuffer *);
	void (*append)(struct OutBuffer*, const void *buf, unsigned int len);
};

// LibUI frontend entry
int ret_entry_ui(struct ReTool *re);

int re_prettify_hex(struct OutBuffer *buf, const char *input);
int re_assemble(enum Arch arch, unsigned int base_addr, struct OutBuffer *buf, struct OutBuffer *err_buf, const char *input);

struct OutBuffer create_mem_buffer(unsigned int size);
struct OutBuffer create_mem_string_buffer(unsigned int size);
struct OutBuffer create_mem_hex_buffer(unsigned int size);
struct OutBuffer create_stdout_hex_buffer();
struct OutBuffer create_stdout_buffer();
const void *get_buffer_contents(struct OutBuffer *buf);

struct __attribute((packed)) Settings {
	uint32_t version;
	uint32_t default_arch;
};
