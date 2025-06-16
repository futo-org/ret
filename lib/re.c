#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <keystone/keystone.h>
#include <keystone/arm64.h>
#include "re.h"
#include "parser.h"
#include <emscripten.h>

static struct OutBuffer re_buf_err;
static struct OutBuffer re_buf_hex;
static struct OutBuffer re_buf_str;

void re_init_globals(void) {
	re_buf_hex = create_mem_hex_buffer(10000);
	re_buf_err = create_mem_string_buffer(10000);
}

struct OutBuffer *re_get_err_buffer(void) { return &re_buf_err; }
struct OutBuffer *re_get_hex_buffer(void) { return &re_buf_hex; }
struct OutBuffer *re_get_str_buffer(void) { return &re_buf_str; }

void re_log(struct ReTool *re, char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

int re_assemble(enum Arch arch, unsigned int base_addr, struct OutBuffer *buf, struct OutBuffer *err_buf, const char *input) {
	buf->clear(buf);
	ks_engine *ks;
	ks_err err;

	ks_arch _ks_arch;
	ks_mode _ks_mode = KS_MODE_LITTLE_ENDIAN;
	if (arch == ARCH_X86_64) {
		_ks_arch = KS_ARCH_X86;
		_ks_mode |= KS_MODE_64;
	} else if (arch == ARCH_ARM64) {
		_ks_arch = KS_ARCH_ARM64;
	} else {
		abort();
	}

	err = ks_open(_ks_arch, _ks_mode, &ks);
    if (err != KS_ERR_OK) {
        printf("ERROR: failed on ks_open(), %d\n", err);
        return -1;
    }

    size_t count;
    unsigned char *encode;
    size_t size;

    err = ks_asm(ks, input, 0, &encode, &size, &count);
	if (err != KS_ERR_OK) {
		char buffer[128];
		printf("ERROR: failed on ks_asm() with count = %zu, error = '%s' (code = %u)\n", count, ks_strerror(ks_errno(ks)), ks_errno(ks));
		err_buf->append(err_buf, buffer, 0);
	} else {
		buf->append(buf, encode, (int)size);
	}

	return 0;
}

int cli_asm_test(void) {
	struct OutBuffer buf = create_stdout_hex_buffer();
	struct OutBuffer err = create_stdout_buffer();

	int rc = re_assemble(ARCH_ARM64, 0, &buf, &err, "nop\nnop\nmov x0, 123000000000000");
	printf("\n");
	return rc;
}

static int cli_asm(struct ReTool *re, enum Arch arch, const char *filename) {
	struct OutBuffer buf = create_stdout_hex_buffer();
	struct OutBuffer err = create_stdout_buffer();

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

	int rc = re_assemble(re->arch, 0, &buf, &err, input);
	printf("\n");
	return rc;
}

int re_prettify_hex(struct OutBuffer *buf, const char *input) {
	buf->clear(buf);
	struct HexPars p;
	create_parser(&p, input, 0);

	while (1) {
		struct Number n = parser_next(&p);
		if (n.eof) return 0;
		buf->append(buf, &n.n, n.data_type_size);
	}

	return 0;
}

int prettify(void) {
	struct HexPars p;
	create_parser(&p, "a a a a a 3 22 30:zd: a c", 0);

	while (1) {
		struct Number n = parser_next(&p);
		if (n.eof) return 0;
		printf("%x\n", (int)n.n);
	}
	
	return 0;
}

static int help(void) {
	printf("ret <arch> <action> <file>\n");
	printf("--x86, --arm, --arm64\n");
	return 0;
}

int main(int argc, char **argv) {
	struct ReTool re;
	re.arch = ARCH_ARM64;

	enum Arch arch = ARCH_ARM64;
	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--x86")) arch = ARCH_X86_64;
		if (!strcmp(argv[i], "--arm")) arch = ARCH_ARM32;
		if (!strcmp(argv[i], "--arm64")) arch = ARCH_ARM64;
		if (!strcmp(argv[i], "--asm")) return cli_asm(&re, arch, argv[i + 1]);
		if (!strcmp(argv[i], "--hex")) return prettify();
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) return help();
	}

	help();

	return 0;
}
