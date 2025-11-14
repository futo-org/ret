#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <keystone/keystone.h>
#include <capstone/capstone.h>
#include "re.h"
#include "cpp/preproc.h"

static struct RetBuffer re_buf_err;
static struct RetBuffer re_buf_hex;
static struct RetBuffer re_buf_mem;
static struct RetBuffer re_buf_str;
static struct RetBuffer re_buf_mirror;

void re_init_globals(void) {
	re_buf_hex = create_mem_hex_buffer();
	re_buf_mem = create_mem_buffer();
	re_buf_err = create_mem_string_buffer();
	re_buf_str = create_mem_string_buffer();
	re_buf_mirror = create_mirror_buffer(&re_buf_mem, &re_buf_hex);
}

struct RetBuffer *re_get_err_buffer(void) { return &re_buf_err; }
struct RetBuffer *re_get_hex_buffer(void) { return &re_buf_hex; }
struct RetBuffer *re_get_str_buffer(void) { return &re_buf_str; }
struct RetBuffer *re_get_mem_buffer(void) { return &re_buf_mem; }
struct RetBuffer *re_get_hex_mem_mirror_buffer(void) { return &re_buf_mirror; }

int re_is_arch_supported(int arch) {
#ifdef RET_SUPPORT_ARM64
	if (arch == ARCH_ARM64) return 1;
#endif
#ifdef RET_SUPPORT_ARM32
	if (arch == ARCH_ARM32 || arch == ARCH_ARM32_THUMB) return 1;
#endif
#ifdef RET_SUPPORT_X86
	if (arch == ARCH_X86) return 1;
#endif
#ifdef RET_SUPPORT_RISCV
	if (arch == ARCH_RISCV) return 1;
#endif
#ifdef RET_SUPPORT_PPC
	if (arch == ARCH_POWERPC) return 1;
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

static int re_open_ks(enum Arch arch, int opt, struct RetBuffer *err_buf, ks_engine **ks) {
	ks_arch _ks_arch;
	ks_mode _ks_mode = KS_MODE_LITTLE_ENDIAN;
	if (arch == ARCH_X86) {
		_ks_arch = KS_ARCH_X86;
		if (opt & RET_BITS_64) _ks_mode |= KS_MODE_64;
		else if (opt & RET_BITS_32) _ks_mode |= KS_MODE_32;
		else if (opt & RET_BITS_16) _ks_mode |= KS_MODE_16;
	} else if (arch == ARCH_ARM64) {
		_ks_arch = KS_ARCH_ARM64;
	} else if (arch == ARCH_ARM32) {
		_ks_arch = KS_ARCH_ARM;
		_ks_mode |= KS_MODE_ARM;
	} else if (arch == ARCH_ARM32_THUMB) {
		_ks_arch = KS_ARCH_ARM;
		_ks_mode |= KS_MODE_THUMB;
	} else if (arch == ARCH_RISCV) {
		_ks_arch = KS_ARCH_RISCV;
		if (opt & RET_BITS_64) _ks_mode |= KS_MODE_RISCV64;
		else if (opt & RET_BITS_32) _ks_mode |= KS_MODE_RISCV32;
		if (opt & RET_RISCV_C) _ks_mode |= KS_MODE_RISCVC;
	} else if (arch == ARCH_POWERPC) {
		_ks_arch = KS_ARCH_PPC;
		if (opt & RET_BIG_ENDIAN) _ks_mode = KS_MODE_BIG_ENDIAN; else _ks_mode = KS_MODE_LITTLE_ENDIAN;
		_ks_mode |= KS_MODE_R_REG_SYNTAX;
		if (opt & RET_BITS_64) _ks_mode |= KS_MODE_PPC64;
		else if (opt & RET_BITS_32) _ks_mode |= KS_MODE_PPC32;
		if (!(_ks_mode & KS_MODE_BIG_ENDIAN) && (_ks_mode & KS_MODE_PPC32)) {
			err_buf->append(err_buf, "32-bit PowerPC Little Endian isn't supported in keystone", 0);
			return -1;
		}
	} else {
		err_buf->append(err_buf, "Unsupported architecture", 0);
		return -1;
	}

	ks_err err = ks_open(_ks_arch, _ks_mode, ks);
	if (err != KS_ERR_OK) {
		buffer_appendf(err_buf, "ks_open failed (%s)\n", ks_strerror(err));
		return -1;
	}

	if (_ks_arch == KS_ARCH_X86) {
		if (opt & RET_SYNTAX_ATT) {
			ks_option(*ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
		} else if (opt & RET_SYNTAX_NASM) {
			ks_option(*ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
		} else if (opt & RET_SYNTAX_MASM) {
			ks_option(*ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_MASM);
		} else if (opt & RET_SYNTAX_GAS) {
			ks_option(*ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_GAS);
		} else {
			ks_option(*ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
		}
	}

	return 0;	
}

static int re_open_cs(enum Arch arch, int opt, struct RetBuffer *err_buf, csh *cs) {
	cs_arch _cs_arch = 0;
	cs_mode _cs_mode = CS_MODE_LITTLE_ENDIAN;
	if (arch == ARCH_X86) {
		_cs_arch = CS_ARCH_X86;
		if (opt & RET_BITS_64) _cs_mode |= CS_MODE_64;
		else if (opt & RET_BITS_32) _cs_mode |= CS_MODE_32;
		else if (opt & RET_BITS_16) _cs_mode |= CS_MODE_16;
	} else if (arch == ARCH_ARM64) {
		_cs_arch = CS_ARCH_AARCH64;
	} else if (arch == ARCH_ARM32) {
		_cs_arch = CS_ARCH_ARM;
	} else if (arch == ARCH_ARM32_THUMB) {
		_cs_arch = CS_ARCH_ARM;
		_cs_mode |= CS_MODE_THUMB;
	} else if (arch == ARCH_RISCV) {
		_cs_arch = CS_ARCH_RISCV;
		if (opt & RET_BITS_64) _cs_mode |= CS_MODE_RISCV64;
		else if (opt & RET_BITS_32) _cs_mode |= CS_MODE_RISCV32;
		if (opt & RET_RISCV_C) _cs_mode |= CS_MODE_RISCVC;
	} else if (arch == ARCH_POWERPC) {
		_cs_arch = CS_ARCH_PPC;
		if (opt & RET_BIG_ENDIAN) _cs_mode = CS_MODE_BIG_ENDIAN; else _cs_mode = CS_MODE_LITTLE_ENDIAN;		
		if (opt & RET_BITS_64) _cs_mode |= CS_MODE_64;
		else if (opt & RET_BITS_32) _cs_mode |= CS_MODE_32;
	} else {
		err_buf->append(err_buf, "Unsupported architecture", 0);
		return -1;
	}

	if (cs_open(_cs_arch, _cs_mode, cs) != CS_ERR_OK) {
		err_buf->append(err_buf, "cs_open failed", 0);
		return -1;
	}

	if (_cs_arch == CS_ARCH_X86) {
		if (opt & RET_SYNTAX_ATT) {
			cs_option(*cs, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
		} else if (opt & RET_SYNTAX_NASM) {
			buffer_appendf(err_buf, "NASM syntax is currently not supported in capstone.\n");
			return -1;
		} else if (opt & RET_SYNTAX_MASM) {
			cs_option(*cs, CS_OPT_SYNTAX, CS_OPT_SYNTAX_MASM);
		} else if (opt & RET_SYNTAX_GAS) {
			buffer_appendf(err_buf, "GAS syntax is currently not supported in capstone.\n");
			return -1;
		} else {
			cs_option(*cs, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
		}
	}
	return 0;
}

struct BreakList {
	unsigned int length;
	unsigned int n_filled;
	struct BreakListMemb {
		unsigned int of;
		unsigned int size;
	}*memb;
};

struct ErrorHandler {
	struct RetBuffer *err_buf;
	int has_errored;
};

static void handler(void *arg, unsigned int of, unsigned int size) {
	struct BreakList *list = arg;
	if (list->n_filled >= list->length) {
		list->length += 1000;
		list->memb = realloc(list->memb, sizeof(struct BreakList) + (sizeof(struct BreakListMemb) * list->length));
	}
	//printf("%u %u\n", of, size);
	list->memb[list->n_filled].of = of;
	list->memb[list->n_filled].size = size;
	list->n_filled++;
}

static void error_handler(void *arg, const char *string, unsigned int size) {
	struct ErrorHandler *handler = arg;
	handler->err_buf->append(handler->err_buf, string, size);
	handler->has_errored = 1;
}

int re_assemble(enum Arch arch, unsigned int base_addr, int options, struct RetBuffer *buf, struct RetBuffer *err_buf, const char *input, int output_options) {
	if (buf == NULL || err_buf == NULL || input == NULL) return -1;
	buf->clear(buf);
	err_buf->clear(err_buf);
	ks_engine *ks;
	ks_err err;

	if (re_open_ks(arch, options, err_buf, &ks)) return -1;

	struct BreakList list;
	list.memb = malloc(sizeof(struct BreakListMemb) * 100);
	list.length = 100;
	list.n_filled = 0;
	ks_set_instruction_stream_handler(ks, handler, &list);

	struct ErrorHandler handler = {
		.err_buf = err_buf,
		.has_errored = 0,
	};
	ks_set_error_message_handler(ks, error_handler, &handler);

	size_t count = 0;
	unsigned char *encode = NULL;
	size_t size = 0;

	//options |= RET_RUN_C_PREPROCESSOR;

	if (options & RET_RUN_C_PREPROCESSOR) {
		re_buf_str.clear(&re_buf_str);
		re_buf_str.append(&re_buf_str, input, 0);
		FILE *i = fmemopen(re_buf_str.buffer, re_buf_str.offset, "r");

		re_buf_mem.clear(&re_buf_mem);
		FILE *o = fmemopen(re_buf_mem.buffer, re_buf_mem.length, "w");

		struct cpp *cpp = cpp_new();
		int ret = cpp_run(cpp, i, o, "stdin");
		if (!ret) {
			buffer_appendf(err_buf, "tinycpp error: %d", ret);
			return -1;
		}

		fclose(i);
		fclose(o);

		input = re_buf_mem.buffer;

		buf->clear(buf);
		err_buf->clear(err_buf);
	}

	err = ks_asm(ks, input, base_addr, &encode, &size, &count);
	if (err != KS_ERR_OK) {
		buffer_appendf(err_buf, "ERROR: %s", ks_strerror(ks_errno(ks)));
		free(list.memb);
		return -1;
	} else if (size == 0) {
		if (handler.has_errored == 0)
			err_buf->append(err_buf, "ERROR: Assembler returned 0 bytes", 0);
		free(list.memb);
		return -1;
	}

	int rc = 0;

	if (output_options & OUTPUT_SPLIT_BY_INSTRUCTION) {
 		const uint8_t *bytecode = (const uint8_t *)encode;
		unsigned int last_of = 0;
		for (unsigned int i = 0; i < list.n_filled; i++) {
			struct BreakListMemb *curr = &list.memb[i];
			if (base_addr > curr->of) continue;
			curr->of -= base_addr;
			if (curr->of > size) continue;
			if (curr->of < last_of) {
				err_buf->append(err_buf, "BUG: Assembly splitter is broken", 0);
				continue;
			}
			if (curr->of > last_of) {
				buffer_append_mode(buf, bytecode + last_of, curr->of - last_of, output_options);
				buffer_appendf(buf, "\n");
			}
			buffer_append_mode(buf, bytecode + curr->of, curr->size, output_options);
			buffer_appendf(buf, "\n");
			last_of = curr->of + curr->size;
		}

		if (last_of < size)
			buffer_append_mode(buf, bytecode + last_of, size - last_of, output_options);
	} else {
		buffer_append_mode(buf, encode, size, output_options);
	}

	ks_free(encode);
	free(list.memb);

	return rc;
}

int re_disassemble(enum Arch arch, unsigned int base_addr, int options, struct RetBuffer *buf, struct RetBuffer *err_buf, const char *input, int parse_options, int output_options) {
	if (buf == NULL || err_buf == NULL || input == NULL) return -1;
	buf->clear(buf);
	err_buf->clear(err_buf);

	re_buf_mem.clear(&re_buf_mem);

	parser_to_buf(input, &re_buf_mem, parse_options, output_options);

	if (re_buf_mem.offset == 0) {
		err_buf->append(err_buf, "ERROR: No bytes to disassemble!", 0);
		return -1;
	}

	csh cs;
	if (re_open_cs(arch, options, err_buf, &cs)) return -1;

	cs_insn *inst = cs_malloc(cs);

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
		
		if (!end_of_valid && is_valid_offset && cs_disasm_iter(cs, &bytecode, &size, &address, inst)) {
			snprintf(inst_buf, sizeof(inst_buf), "%s %s\n", inst->mnemonic, inst->op_str);
			buf->append(buf, inst_buf, 0);
		} else {
			if (!(options & RET_AGGRESSIVE_DISASM))
				end_of_valid = 1;
			if (arch == ARCH_X86 && (options & RET_SYNTAX_NASM || options & RET_SYNTAX_MASM)) {
				snprintf(inst_buf, sizeof(inst_buf), "db 0x%02x\n", *bytecode);
			} else {
				snprintf(inst_buf, sizeof(inst_buf), ".byte 0x%02x\n", *bytecode);
			}
			buf->append(buf, inst_buf, 0);
			size--;
			address++;
			bytecode++;
		}
	}

	cs_close(&cs);
	cs_free(inst, 1);

	return 0;
}

static int cli_asm(enum Arch arch, int opt, const char *filename) {
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

	int rc = re_assemble(arch, 0x0, opt, &re_buf_hex, &re_buf_err, input, OUTPUT_AS_U8 | OUTPUT_SPLIT_BY_INSTRUCTION);
	if (rc) {
		printf("%s\n", re_buf_err.buffer);
	} else {
		printf("%s\n", re_buf_hex.buffer);
	}
	free(input);
	return rc;
}

int cli_disasm(enum Arch arch, int opt, const char *filename) {
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

	int rc = re_disassemble(arch, 0x0, opt, &re_buf_str, &re_buf_err, input, PARSE_AS_AUTO, OUTPUT_AS_AUTO);
	if (rc) {
		return -1;
	}
	printf("%s\n", re_buf_str.buffer);

	free(input);
	return 0;
}

int cli_hex(const char *input) {
	struct RetBuffer buf = create_mem_hex_buffer();
	parser_to_buf(input, &buf, PARSE_AS_AUTO, OUTPUT_AS_U32);
	printf("%s\n", buf.buffer);	
	return 0;
}

static int help(void) {
	printf("ret <arch> <action> <file>\n");
	printf("--x86, --arm, --thumb, --arm64, --rv64\n");
	printf("--asm <filename>\n");
	printf("--dis <filename>\n");
	printf("--hex <string>\n");
	return 0;
}

static int test(void) {
	if (test_buffer()) return -1;

	if (re_assemble(ARCH_ARM64, 0, 0, &re_buf_mirror, &re_buf_err, "mov x0, #0x123\n", OUTPUT_AS_U8 | OUTPUT_SPLIT_BY_FOUR)) return -1;

	if (re_assemble(ARCH_ARM32, 0, 0, &re_buf_mirror, &re_buf_err, "mov r0, 0x123\n", OUTPUT_AS_U8 | OUTPUT_SPLIT_BY_FOUR)) return -1;
	if (re_assemble(ARCH_ARM32_THUMB, 0, 0, &re_buf_mirror, &re_buf_err, "mov r0, 0x123\n", OUTPUT_AS_U8 | OUTPUT_SPLIT_BY_FOUR)) return -1;

	printf("----- Test Parser ------\n");

	parser_to_buf("1020304050607080", &re_buf_mirror, PARSE_AS_AUTO, OUTPUT_AS_U8);
	printf("%s\n", (const char *)buffer_get_contents(&re_buf_hex));

	return 0;
}

static int test_emu(enum Arch arch, int opt, const char *filename) {
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

	if (re_assemble(arch, 0, opt, &re_buf_mem, &re_buf_err, input, 0)) {
		printf("%s\n", re_buf_err.buffer);
		return -1;
	}

	if (re_emulator(arch, opt, 0x0, &re_buf_mem, &re_buf_err)) {
		printf("%s\n", re_buf_err.buffer);
		return -1;
	}

	printf("%s\n", re_buf_err.buffer);

	return 0;
}

int test_vm(void);

int main(int argc, char **argv) {
	re_init_globals();

	enum Arch arch = ARCH_ARM64;
	int opt = RET_BITS_64 | RET_SYNTAX_INTEL;
	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--x86")) arch = ARCH_X86;
		if (!strcmp(argv[i], "--arm")) arch = ARCH_ARM32;
		if (!strcmp(argv[i], "--thumb")) arch = ARCH_ARM32_THUMB;
		if (!strcmp(argv[i], "--arm64")) arch = ARCH_ARM64;
		if (!strcmp(argv[i], "--rv64")) arch = ARCH_RISCV;
		if (!strcmp(argv[i], "--ppc32")) {
			arch = ARCH_POWERPC;
			opt &= ~(RET_BITS_64); opt |= (RET_BITS_32);
		}

		if (!strcmp(argv[i], "--test")) return test();
		if (!strcmp(argv[i], "--asm")) return cli_asm(arch, opt, argv[i + 1]);
		if (!strcmp(argv[i], "--dis")) return cli_disasm(arch, opt, argv[i + 1]);
		if (!strcmp(argv[i], "--hex")) return cli_hex(argv[i + 1]);
		if (!strcmp(argv[i], "--emu")) return test_emu(arch, opt, argv[i + 1]);
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) return help();
	}

	help();

	return 0;
}
