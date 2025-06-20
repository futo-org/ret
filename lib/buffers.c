#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "re.h"

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

static int is_end_of_4(int c) {
	return (c >= 3) && ((c - 3) % 4 == 0);
}

static void buf_clear(struct OutBuffer *buf) {
	buf->offset = 0;
	buf->counter = 0;
}
static void buf_append(struct OutBuffer *buf, const void *in, unsigned int len) {
	if (buf->length < (len + buf->offset)) {
		buf->buffer = realloc(buf->buffer, buf->length + len + 1000);
	}
	memcpy(buf->buffer + buf->offset, in, len);
	buf->offset += len;
}
static void buf_append_hex(struct OutBuffer *buf, const void *in, unsigned int len) {
	unsigned int max_str_len = 32 * len;
	if (buf->length < (max_str_len + buf->offset)) {
		buf->buffer = realloc(buf->buffer, buf->length + max_str_len + 1000);
	}

	unsigned int data_type_size = 0;
	if (buf->output_options & OUTPUT_AS_U8) data_type_size = 1;
	if (buf->output_options & OUTPUT_AS_U16) data_type_size = 2;
	if (buf->output_options & OUTPUT_AS_U32) data_type_size = 4;
	
	for (unsigned int i = 0; i < len; i += data_type_size) {
		if (data_type_size == 1) {
			char ch = ' ';
			if (is_end_of_4(buf->counter)) {
				ch = '\n';
			}

			uint8_t b;
			read_u8((const uint8_t *)in + i, &b);
			buf->offset += sprintf(buf->buffer + buf->offset, "%02x%c", b, ch);
		} else if (data_type_size == 2) {
			uint16_t b;
			read_u16((const uint8_t *)in + i, &b);
			buf->offset += sprintf(buf->buffer + buf->offset, "%04x%c", b, '\n');
		} else if (data_type_size == 4) {
			uint32_t b;
			read_u32((const uint8_t *)in + i, &b);
			buf->offset += sprintf(buf->buffer + buf->offset, "%08x%c", b, '\n');
		}
		buf->counter++;
	}
}
static void buf_append_string(struct OutBuffer *buf, const void *in, unsigned int len) {
	const char *str = in;
	unsigned int max_str_len = strlen(str) + 1;
	if (buf->length < (max_str_len + buf->offset)) {
		buf->buffer = realloc(buf->buffer, buf->length + max_str_len + 1000);
	}
	memcpy(buf->buffer + buf->offset, str, max_str_len);
	buf->offset += max_str_len - 1;
}

struct OutBuffer create_mem_buffer(unsigned int size) {
	struct OutBuffer buf = {0};
	buf.buffer = malloc(10000);
	buf.length = 10000;
	buf.offset = 0;
	buf.clear = buf_clear;
	buf.append = buf_append;
	return buf;
}

struct OutBuffer create_mem_string_buffer(unsigned int size) {
	struct OutBuffer buf = {0};
	buf.buffer = malloc(10000);
	buf.length = 10000;
	buf.offset = 0;
	buf.clear = buf_clear;
	buf.append = buf_append_string;
	return buf;
}

struct OutBuffer create_mem_hex_buffer(unsigned int size) {
	struct OutBuffer buf = {0};
	buf.buffer = malloc(10000);
	buf.length = 10000;
	buf.offset = 0;
	buf.clear = buf_clear;
	buf.append = buf_append_hex;
	buf.counter = 0;
	return buf;
}

static void stdio_clear(struct OutBuffer *buf) {}
static void stdio_append_hex(struct OutBuffer *buf, const void *in, unsigned int len) {
	for (unsigned int i = 0; i < len; i++) {
		if (is_end_of_4(buf->length)) {
			printf("\n");
		}

		printf("%02x ", ((uint8_t *)in)[i]);

		buf->length++;
	}
}
static void stdio_append(struct OutBuffer *buf, const void *in, unsigned int len) {
	(void)buf;
	(void)len;
	printf("%s", (const char *)in);
	fflush(stdout);
}
const void *get_buffer_contents(struct OutBuffer *buf) {
	return buf->buffer;
}

struct OutBuffer create_stdout_hex_buffer(void) {
	struct OutBuffer buf;
	buf.length = 0;
	buf.clear = stdio_clear;
	buf.append = stdio_append_hex;
	return buf;
}

struct OutBuffer create_stdout_buffer(void) {
	struct OutBuffer buf;
	buf.length = 0;
	buf.clear = stdio_clear;
	buf.append = stdio_append;
	return buf;
}
