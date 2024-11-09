#pragma once
#include <stdint.h>

enum Arch {
	ARCH_ARM,
	ARCH_X86,
	ARCH_X86_64,
	ARCH_ARM64,
};

struct ReTool {
	enum Arch arch;
};

struct OutBuffer {
	void *handle;
	char *buffer;
	int offset;
	int length;
	void (*clear)(struct OutBuffer *);
	void (*append)(struct OutBuffer*, const void *buf, int len);
};

// Frontend methods
int ret_entry_ui(struct ReTool *re);

int prettify_hex(struct ReTool *re, struct OutBuffer *buf, const char *input);
int re_asm(struct ReTool *re, struct OutBuffer *buf, struct OutBuffer *err_buf, const char *input);

int re_assemble(struct ReTool *re, const char *input, struct OutBuffer *buf);
int re_disassemble(struct ReTool *re, const char *input);
int re_format_hex(struct ReTool *re, const char *input);
int re_save_hex(struct ReTool *re, const char *input);
int re_export_c_bytes(struct ReTool *re, const char *input);

struct OutBuffer create_mem_buffer(int size);
struct OutBuffer create_stdout_hex_buffer();
struct OutBuffer create_stdout_buffer();

struct __attribute((packed)) Settings {
	uint32_t version;
	uint32_t default_arch;
};
