#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "re.h"

static void buf_clear(struct OutBuffer *buf) {
	buf->offset = 0;
}
static void buf_append(struct OutBuffer *buf, const void *in, int len) {
	if (buf->length - buf->offset <= len) {
		buf->buffer = realloc(buf->buffer, buf->length + 1000);
	}
	memcpy(buf->buffer, in, len);
	buf->offset += len;
}

struct OutBuffer create_mem_buffer(int size) {
	struct OutBuffer buf;
	buf.buffer = malloc(10000);
	buf.length = 10000;
	buf.offset = 0;
	buf.clear = buf_clear;
	buf.append = buf_append;
	return buf;
}

static void stdio_clear(struct OutBuffer *buf) {}
static void stdio_append_hex(struct OutBuffer *buf, const void *in, int len) {
	for (int i = 0; i < len; i++) {
		if ((buf->length & 0b11) == 0 && buf->length != 0) {
			printf("\n");
		}

		printf("%02x ", ((uint8_t *)in)[i]);

		buf->length++;
	}
}
static void stdio_append(struct OutBuffer *buf, const void *in, int len) {
	printf("%s", (const char *)in);
	fflush(stdout);
}
struct OutBuffer create_stdout_hex_buffer() {
	struct OutBuffer buf;
	buf.length = 0;
	buf.clear = stdio_clear;
	buf.append = stdio_append_hex;
	return buf;
}

struct OutBuffer create_stdout_buffer() {
	struct OutBuffer buf;
	buf.length = 0;
	buf.clear = stdio_clear;
	buf.append = stdio_append;
	return buf;
}
