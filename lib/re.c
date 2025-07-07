#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <keystone/keystone.h>
#include <keystone/arm64.h>
#include <capstone/capstone.h>
#include "re.h"

static struct RetBuffer re_buf_err;
static struct RetBuffer re_buf_hex;
static struct RetBuffer re_buf_mem;
static struct RetBuffer re_buf_str;

void re_init_globals(void) {
	re_buf_hex = create_mem_hex_buffer();
	re_buf_mem = create_mem_buffer();
	re_buf_err = create_mem_string_buffer();
	re_buf_str = create_mem_string_buffer();
}

struct RetBuffer *re_get_err_buffer(void) { return &re_buf_err; }
struct RetBuffer *re_get_hex_buffer(void) { return &re_buf_hex; }
struct RetBuffer *re_get_str_buffer(void) { return &re_buf_str; }
struct RetBuffer *re_get_mem_buffer(void) { return &re_buf_mem; }

int re_is_arch_supported(int arch) {
#ifdef RET_SUPPORT_ARM64
	if (arch == ARCH_ARM64) return 1;
#endif
#ifdef RET_SUPPORT_ARM32
	if (arch == ARCH_ARM32) return 1;
#endif
#ifdef RET_SUPPORT_X86
	if (arch == ARCH_X86 || arch == ARCH_X86_64) return 1;
#endif
	return 0;
}

int re_is_unicorn_supported(void) {
#ifdef RET_SUPPORT_UNICORN
	return 1;
#else
	return 0;
#endif
}

int re_assemble(enum Arch arch, unsigned int base_addr, int syntax, struct RetBuffer *buf, struct RetBuffer *err_buf, const char *input, int output_options) {
	if (buf == NULL || err_buf == NULL || input == NULL) return -1;
	buf->clear(buf);
	buf->clear(err_buf);
	ks_engine *ks;
	ks_err err;

	ks_arch _ks_arch;
	ks_mode _ks_mode = KS_MODE_LITTLE_ENDIAN;
	if (arch == ARCH_X86_64) {
		_ks_arch = KS_ARCH_X86;
		_ks_mode |= KS_MODE_64;
	} else if (arch == ARCH_ARM64) {
		_ks_arch = KS_ARCH_ARM64;
	} else if (arch == ARCH_ARM32) {
		_ks_arch = KS_ARCH_ARM;
		_ks_mode |= KS_MODE_ARM;
	} else if (arch == ARCH_ARM32_THUMB) {
		_ks_arch = KS_ARCH_ARM;
		_ks_mode |= KS_MODE_THUMB;
	} else if (arch == ARCH_RISCV32) {
		_ks_arch = KS_ARCH_RISCV;
		_ks_mode |= KS_MODE_RISCV32;
	} else if (arch == ARCH_RISCV64) {
		_ks_arch = KS_ARCH_RISCV;
		_ks_mode |= KS_MODE_RISCV64;
	} else {
		err_buf->append(err_buf, "Unsupported architecture", 0);
		return -1;
	}

	err = ks_open(_ks_arch, _ks_mode, &ks);
	if (err != KS_ERR_OK) {
		buffer_appendf(err_buf, "ks_open failed (%s)\n", ks_strerror(err));
		return -1;
	}

	if (_ks_arch == KS_ARCH_X86) {
		if (syntax == RET_SYNTAX_INTEL) {
			ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
		} else if (syntax == RET_SYNTAX_ATT) {
			ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
		} else if (syntax == RET_SYNTAX_NASM) {
			ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
		} else if (syntax == RET_SYNTAX_MASM) {
			ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_MASM);
		} else if (syntax == RET_SYNTAX_GAS) {
			ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_GAS);
		} else {
			buffer_appendf(err_buf, "Invalid syntax code\n");
			return -1;
		}
	}

	size_t count = 0;
	unsigned char *encode = NULL;
	size_t size = 0;

	err = ks_asm(ks, input, base_addr, &encode, &size, &count);
	if (err != KS_ERR_OK) {
		char buffer[128];
		snprintf(buffer, sizeof(buffer), "ERROR: failed on ks_asm() with count = %zu, error = '%s' (code = %u)", count, ks_strerror(ks_errno(ks)), ks_errno(ks));
		printf("%s\n", buffer);
		err_buf->append(err_buf, buffer, 0);
		return -1;
	} else if (size == 0) {
		err_buf->append(err_buf, "ERROR: Assembler returned 0 bytes", 0);
		return -1;
	}

	buffer_append_mode(buf, encode, size, output_options);
	ks_free(encode);

	return 0;
}

int re_disassemble(enum Arch arch, unsigned int base_addr, int syntax, struct RetBuffer *buf, struct RetBuffer *err_buf, const char *input, int parse_options, int output_options) {
	if (buf == NULL || err_buf == NULL || input == NULL) return -1;
	buf->clear(buf);
	err_buf->clear(err_buf);

	re_buf_mem.clear(&re_buf_mem);

	parser_to_buf(input, &re_buf_mem, parse_options, output_options);

	csh handle;

	cs_arch _cs_arch = 0;
	cs_mode _cs_mode = CS_MODE_LITTLE_ENDIAN;
	if (arch == ARCH_X86_64) {
		_cs_arch = CS_ARCH_X86;
		_cs_mode |= CS_MODE_64;
	} else if (arch == ARCH_ARM64) {
		_cs_arch = CS_ARCH_AARCH64;
	} else if (arch == ARCH_ARM32) {
		_cs_arch = CS_ARCH_ARM;
	} else if (arch == ARCH_ARM32_THUMB) {
		_cs_arch = CS_ARCH_ARM;
		_cs_mode |= CS_MODE_THUMB;
	} else if (arch == ARCH_RISCV64) {
		_cs_arch = CS_ARCH_RISCV;
		_cs_mode |= CS_MODE_RISCV64;
	} else if (arch == ARCH_RISCV32) {
		_cs_arch = CS_ARCH_RISCV;
		_cs_mode |= CS_MODE_RISCV32;
	} else {
		err_buf->append(err_buf, "Unsupported architecture", 0);
		return -1;
	}

	if (cs_open(_cs_arch, _cs_mode, &handle) != CS_ERR_OK) {
		err_buf->append(err_buf, "cs_open failed", 0);
		return -1;
	}

	if (_cs_arch == CS_ARCH_X86) {
		if (syntax == RET_SYNTAX_INTEL) {
			cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
		} else if (syntax == RET_SYNTAX_ATT) {
			cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
		} else if (syntax == RET_SYNTAX_NASM) {
			buffer_appendf(err_buf, "NASM syntax is currently not supported in capstone.\n");
			return -1;
		} else if (syntax == RET_SYNTAX_MASM) {
			cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_MASM);
		} else if (syntax == RET_SYNTAX_GAS) {
			buffer_appendf(err_buf, "GAS syntax is currently not supported in capstone.\n");
			return -1;
		} else {
			buffer_appendf(err_buf, "Invalid syntax code\n");
			return -1;
		}
	}

	if (re_buf_mem.offset == 0) {
		err_buf->append(err_buf, "ERROR: No bytes to disassemble!", 0);
		return -1;
	}

	cs_insn *inst = cs_malloc(handle);

	const uint8_t *bytecode = (const uint8_t *)re_buf_mem.buffer;
	size_t size = re_buf_mem.offset;
	uint64_t address = base_addr;
	int end_of_valid = 0;
	while (size != 0) {
		char inst_buf[512];
		int is_valid_offset = 1;
		if ((arch == ARCH_ARM64 || arch == ARCH_ARM32) && (address & 0b11) != 0) {
			is_valid_offset = 0;
		}
		
		if (!end_of_valid && is_valid_offset && cs_disasm_iter(handle, &bytecode, &size, &address, inst)) {
			snprintf(inst_buf, sizeof(inst_buf), "%s %s\n", inst->mnemonic, inst->op_str);
			buf->append(buf, inst_buf, 0);
		} else {
			if (syntax & RET_AGGRESSIVE_DISASM)
				end_of_valid = 1;
			// TODO: Print as u32 for arm64 and arm32
			if (arch == ARCH_X86_64 || arch == ARCH_X86) {
				snprintf(inst_buf, sizeof(inst_buf), "db 0x%02x\n", ((const uint8_t *)re_buf_mem.buffer)[size]);
			} else {
				snprintf(inst_buf, sizeof(inst_buf), ".byte 0x%02x\n", ((const uint8_t *)re_buf_mem.buffer)[size]);
			}
			buf->append(buf, inst_buf, 0);
			size--;
			address++;
			bytecode++;
		}
	}

	cs_close(&handle);

	return 0;
}

static int cli_asm(enum Arch arch, const char *filename) {
	struct RetBuffer buf = create_mem_hex_buffer();
	struct RetBuffer err = create_stdout_buffer();

	FILE *f = fopen(filename, "rb");
	if (!f) {
		printf("Error opening %s\n", filename);
		return -1;
	}

	fseek(f, 0, SEEK_END);
	size_t sz = ftell(f);
	rewind(f);

	char *input = malloc(sz + 1);

	if (fread(input, 1, sz, f) != sz) {
		free(input);
		fclose(f);
		return -1;
	}

	fclose(f);
	input[sz] = '\0';

	int rc = re_assemble(arch, 0, 0, &re_buf_hex, &re_buf_err, input, OUTPUT_AS_AUTO);
	printf("%s\n", re_buf_hex.buffer);
	free(input);
	return rc;
}

int cli_disasm(enum Arch arch, const char *filename) {
	FILE *f = fopen(filename, "rb");
	if (!f) {
		printf("Error opening %s\n", filename);
		return -1;
	}

	fseek(f, 0, SEEK_END);
	size_t sz = ftell(f);
	rewind(f);

	char *input = malloc(sz + 1);

	if (fread(input, 1, sz, f) != sz) {
		free(input);
		fclose(f);
		return -1;
	}

	fclose(f);
	input[sz] = '\0';

	int rc = re_disassemble(arch, 0x0, 0, &re_buf_str, &re_buf_err, input, PARSE_AS_AUTO, OUTPUT_AS_AUTO);
	if (rc) {
		return -1;
	}
	printf("%s\n", re_buf_str.buffer);

	free(input);
	return 0;
}

int cli_hex(enum Arch arch, const char *input) {
	struct RetBuffer buf = create_mem_hex_buffer();
	parser_to_buf(input, &buf, PARSE_AS_AUTO, OUTPUT_AS_U32);
	printf("%s\n", buf.buffer);	
	return 0;
}

static int help(void) {
	printf("ret <arch> <action> <file>\n");
	printf("--x86, --arm, --arm64\n");
	printf("--asm <filename>\n");
	printf("--dis <filename>\n");
	printf("--hex <string>\n");
	return 0;
}

int main(int argc, char **argv) {
	re_init_globals();
	enum Arch arch = ARCH_ARM64;
	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--x86")) arch = ARCH_X86_64;
		if (!strcmp(argv[i], "--arm")) arch = ARCH_ARM32;
		if (!strcmp(argv[i], "--arm64")) arch = ARCH_ARM64;
		if (!strcmp(argv[i], "--rv64")) arch = ARCH_RISCV64;
		
		if (!strcmp(argv[i], "--asm")) return cli_asm(arch, argv[i + 1]);
		if (!strcmp(argv[i], "--dis")) return cli_disasm(arch, argv[i + 1]);
		if (!strcmp(argv[i], "--hex")) return cli_hex(arch, argv[i + 1]);
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) return help();
	}

	help();

	return 0;
}
