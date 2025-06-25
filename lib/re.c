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

int re_assemble(enum Arch arch, unsigned int base_addr, struct RetBuffer *buf, struct RetBuffer *err_buf, const char *input, int output_options) {
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

int re_disassemble(enum Arch arch, unsigned int base_addr, struct RetBuffer *buf, struct RetBuffer *err_buf, const char *input) {
	buf->clear(buf);
	err_buf->clear(err_buf);

	re_buf_mem.clear(&re_buf_mem);

	parser_to_buf(input, &re_buf_mem, PARSE_AS_AUTO, OUTPUT_AS_AUTO);

	csh handle;
	cs_insn *insn;
	size_t count;
	//ks_opt_value syntax = KS_OPT_SYNTAX_GAS;
	//ks_option

	cs_arch _cs_arch = 0;
	cs_mode _cs_mode = CS_MODE_LITTLE_ENDIAN;
	if (arch == ARCH_X86_64) {
		_cs_arch = CS_ARCH_X86;
		_cs_mode |= CS_MODE_64;
		//syntax = KS_OPT_SYNTAX_NASM;
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

	if (re_buf_mem.offset == 0) {
		err_buf->append(err_buf, "ERROR: No bytes to disassemble!", 0);
		return -1;
	}

	count = cs_disasm(handle, (const uint8_t *)re_buf_mem.buffer, re_buf_mem.offset, base_addr, 0, &insn);
	if (count > 0) {
		unsigned int code_size = 0;
		for (size_t j = 0; j < count; j++) {
			char inst_buf[512];
			// TODO: if inst[j].illegal, then do .int 0xdeadbeef
			snprintf(inst_buf, sizeof(inst_buf), "%s %s\n", insn[j].mnemonic, insn[j].op_str);
			code_size += insn[j].size;
			buf->append(buf, inst_buf, 0);
		}

		for (; code_size < re_buf_mem.offset; code_size++) {
			char inst_buf[512];
			if (arch == ARCH_X86_64 || arch == ARCH_X86) {
				snprintf(inst_buf, sizeof(inst_buf), "db 0x%02x\n", ((const uint8_t *)re_buf_mem.buffer)[code_size]);
			} else {
				snprintf(inst_buf, sizeof(inst_buf), ".byte 0x%02x\n", ((const uint8_t *)re_buf_mem.buffer)[code_size]);
			}
			buf->append(buf, inst_buf, 0);
		}

		cs_free(insn, count);
	} else {
		err_buf->append(err_buf, "ERROR: Failed to disassemble given code!", 0);
		return -1;
	}

	cs_close(&handle);

	return 0;
}

int cli_asm_test(void) {
	struct RetBuffer buf = create_stdout_hex_buffer();
	struct RetBuffer err = create_stdout_buffer();

	int rc = re_assemble(ARCH_ARM64, 0, &buf, &err, "nop\nnop\nmov x0, 123000000000000", OUTPUT_AS_AUTO);
	printf("\n");
	return rc;
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

	int rc = re_assemble(arch, 0, &buf, &err, input, OUTPUT_AS_AUTO);
	printf("\n");
	return rc;
}

int prettify(void) {
	struct RetBuffer buf = create_mem_hex_buffer();
	parser_to_buf("12 34 56 78 12 34 56 78 91", &buf, PARSE_AS_AUTO, OUTPUT_AS_U32);
	printf("%s\n", buf.buffer);	
	return 0;
}

static int help(void) {
	printf("ret <arch> <action> <file>\n");
	printf("--x86, --arm, --arm64\n");
	return 0;
}

int main(int argc, char **argv) {
	enum Arch arch = ARCH_ARM64;
	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--x86")) arch = ARCH_X86_64;
		if (!strcmp(argv[i], "--arm")) arch = ARCH_ARM32;
		if (!strcmp(argv[i], "--arm64")) arch = ARCH_ARM64;
		if (!strcmp(argv[i], "--rv64")) arch = ARCH_RISCV64;
		
		if (!strcmp(argv[i], "--asm")) return cli_asm(arch, argv[i + 1]);
		if (!strcmp(argv[i], "--hex")) return prettify();
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) return help();
	}

	help();

	return 0;
}
