// Ret Buffer/piping layer
// This allows the assembler/disassembler/parser to input and output in a variety of different
// ways through a common API.
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include "re.h"

static int is_end_of_4(unsigned int c) {
	return (c >= 3) && ((c - 3) % 4 == 0);
}

static void to_bits(uint32_t v, int n_bits, char *buffer) {
	int c = 0;
	for (int i = (n_bits - 1); i >= 0; i--) {
		buffer[c] = (char)((v & (1 << i)) ? '1' : '0');
		c++;
	}
	buffer[c] = '\0';
}

static void buffer_clear(struct RetBuffer *buf) {
	buf->offset = 0;
	buf->counter = 0;
}

static void buffer_append_string(struct RetBuffer *buf, const void *in, unsigned int len) {
	const char *str = in;
	unsigned int max_str_len = len;
	if (max_str_len == 0) max_str_len = strlen(str);
	if (buf->length < (max_str_len + 1 + buf->offset)) {
		buf->buffer = realloc(buf->buffer, buf->length + max_str_len + 1 + 1000);
		buf->length = buf->length + max_str_len + 1 + 1000;
		if (buf->buffer == NULL) abort();
	}
	memcpy(buf->buffer + buf->offset, str, max_str_len);
	buf->offset += max_str_len;
	buf->buffer[buf->offset] = '\0'; // ensure null termination if len != 0
}

static void buffer_append_mem(struct RetBuffer *buf, const void *in, unsigned int len) {
	if (buf->length < (len + buf->offset)) {
		buf->buffer = realloc(buf->buffer, buf->length + len + 1000);
		buf->length = buf->length + len + 1000;
	}
	memcpy(buf->buffer + buf->offset, in, len);
	buf->offset += len;
}
static void buffer_append_hex(struct RetBuffer *buf, const void *in, unsigned int len) {
	if (len == 0) {
		buffer_append_string(buf, in, 0);
		return;
	}
	unsigned int max_str_len = 32 * len;
	if (buf->length < (max_str_len + buf->offset)) {
		buf->buffer = realloc(buf->buffer, buf->length + max_str_len + 1000);
		buf->length = buf->length + max_str_len + 1000;
	}

	unsigned int data_type_size = 1;
	if (buf->output_options & OUTPUT_AS_U8) data_type_size = 1;
	if (buf->output_options & OUTPUT_AS_U16) data_type_size = 2;
	if (buf->output_options & OUTPUT_AS_U32) data_type_size = 4;
	if (buf->output_options & OUTPUT_AS_U32_BINARY) data_type_size = 4;
	if (buf->output_options & OUTPUT_AS_C_ARRAY) data_type_size = 1;

	for (unsigned int i = 0; i < len; i += data_type_size) {
		if (data_type_size == 1) {
			char ch = ' ';
			if (buf->output_options & OUTPUT_SPLIT_BY_FOUR) {
				if (is_end_of_4(buf->counter)) {
					ch = '\n';
				}
			}

			uint8_t b;
			read_u8((const uint8_t *)in + i, &b);
			if (buf->output_options & OUTPUT_AS_C_ARRAY) {
				buf->offset += sprintf(buf->buffer + buf->offset, "0x%02x, ", b);
			} else if (buf->output_options & OUTPUT_AS_U8_BINARY) {
				char binbuf[9];
				to_bits(b, 8, binbuf);
				buf->offset += sprintf(buf->buffer + buf->offset, "0b%s%c", binbuf, ch);				
			} else {
				buf->offset += sprintf(buf->buffer + buf->offset, "%02x%c", b, ch);
			}
		} else if (data_type_size == 2) {
			if (i + 2 >= len + 1) break;
			uint16_t b;
			read_u16((const uint8_t *)in + i, &b);
			buf->offset += sprintf(buf->buffer + buf->offset, "%04x%c", b, '\n');
		} else if (data_type_size == 4) {
			// each byte of u32 is read incrementally to not overflow.
			// Ideally len would be a factor of 4. But sometimes it's not.
			const uint8_t *b = (const uint8_t *)in + i;
			uint32_t out = 0;
			if (i + 1 < len + 1) out |= (uint32_t)b[0];
			if (i + 2 < len + 1) out |= ((uint32_t)b[1] << 8);
			if (i + 3 < len + 1) out |= ((uint32_t)b[2] << 16);
			if (i + 4 < len + 1) out |= ((uint32_t)b[3] << 24);

			if (buf->output_options & OUTPUT_AS_U32_BINARY) {
				char binbuf[33];
				to_bits(out, 32, binbuf);
				buf->offset += sprintf(buf->buffer + buf->offset, "0b%s%c", binbuf, '\n');
			} else {
				buf->offset += sprintf(buf->buffer + buf->offset, "%08x%c", out, '\n');
			}
		}
		buf->counter++;
	}
}

static void stdio_clear(struct RetBuffer *buf) {}
static void stdio_append_hex(struct RetBuffer *buf, const void *in, unsigned int len) {
	for (unsigned int i = 0; i < len; i++) {
		if (is_end_of_4(buf->length)) {
			printf("\n");
		}

		printf("%02x ", ((uint8_t *)in)[i]);

		buf->length++;
	}
}
static void stdio_append(struct RetBuffer *buf, const void *in, unsigned int len) {
	(void)buf;
	(void)len;
	printf("%s", (const char *)in);
	fflush(stdout);
}

const void *buffer_get_contents(struct RetBuffer *buf) {
	return buf->buffer;
}

unsigned int buffer_get_data_length(struct RetBuffer *buf) {
	return buf->offset;
}

void buffer_to_buffer(struct RetBuffer *buf_out, struct RetBuffer *buf_in, int output_options) {
	if (buf_in == NULL) return;
	if (buf_out == NULL) return;
	int option = buf_out->output_options;
	buf_out->output_options = output_options;
	buf_out->clear(buf_out);
	buf_out->append(buf_out, buf_in->buffer, buf_in->offset);
	buf_out->output_options = option;
}

void buffer_appendf(struct RetBuffer *buf, const char *fmt, ...) {
	char buffer[512] = {0};
	va_list args;
	va_start(args, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);
	buf->append(buf, buffer, 0);
}

void buffer_append_mode(struct RetBuffer *buf, const void *data, unsigned int length, int output_options) {
	if (buf == NULL) return;
	if (data == NULL) return;
	int temp = buf->output_options;
	buf->output_options = output_options;
	buf->append(buf, data, length);
	buf->output_options = temp;
}

struct RetBuffer create_mem_buffer(void) {
	struct RetBuffer buf = {0};
	buf.buffer = malloc(10000);
	buf.length = 10000;
	buf.offset = 0;
	buf.clear = buffer_clear;
	buf.append = buffer_append_mem;
	return buf;
}

struct RetBuffer create_mem_string_buffer(void) {
	struct RetBuffer buf = {0};
	buf.buffer = malloc(10000);
	buf.length = 10000;
	buf.offset = 0;
	buf.clear = buffer_clear;
	buf.append = buffer_append_string;
	return buf;
}

struct RetBuffer create_mem_hex_buffer(void) {
	struct RetBuffer buf = {0};
	buf.buffer = malloc(10000);
	buf.length = 10000;
	buf.offset = 0;
	buf.clear = buffer_clear;
	buf.append = buffer_append_hex;
	buf.counter = 0;
	return buf;
}

struct RetBuffer create_stdout_hex_buffer(void) {
	struct RetBuffer buf = {0};
	buf.length = 0;
	buf.clear = stdio_clear;
	buf.append = stdio_append_hex;
	return buf;
}

struct RetBuffer create_stdout_buffer(void) {
	struct RetBuffer buf = {0};
	buf.length = 0;
	buf.clear = stdio_clear;
	buf.append = stdio_append;
	return buf;
}

static void mirror_clear(struct RetBuffer *buf) {
	if (buf->mirror1 == NULL || buf->mirror2 == NULL) abort();
	buf->mirror1->clear(buf->mirror1);
	buf->mirror2->clear(buf->mirror2);
}
static void mirror_append(struct RetBuffer *buf, const void *in, unsigned int len) {
	if (buf->mirror1 == NULL || buf->mirror2 == NULL) abort();
	int temp1 = buf->mirror1->output_options;
	int temp2 = buf->mirror2->output_options;
	buf->mirror1->output_options = buf->output_options;
	buf->mirror2->output_options = buf->output_options;

	buf->mirror1->append(buf->mirror1, in, len);
	buf->mirror2->append(buf->mirror2, in, len);

	buf->mirror1->output_options = temp1;
	buf->mirror2->output_options = temp2;
}

struct RetBuffer create_mirror_buffer(struct RetBuffer *buf1, struct RetBuffer *buf2) {
	struct RetBuffer buf = {0};
	buf.length = 0;
	buf.clear = mirror_clear;
	buf.append = mirror_append;
	buf.mirror1 = buf1;
	buf.mirror2 = buf2;
	return buf;
}

int test_buffer(void) {
	struct RetBuffer b1 = create_mem_buffer();
	struct RetBuffer b2 = create_mem_hex_buffer();
	struct RetBuffer mirror = create_mirror_buffer(&b1, &b2);

	char data[] = "Hello, World";
	mirror.append(&mirror, data, sizeof(data));

	printf("%s\n", b2.buffer);

	return 0;
}
