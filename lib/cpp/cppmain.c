#include "preproc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char** argv) {
	int c; char* tmp;
	struct cpp* cpp = cpp_new();

	char input[] = "#define ASD 1\nASD\n";
	void *output = malloc(500);

	FILE *i = fmemopen(input, sizeof(input), "r");
	//FILE *o = fmemopen(output, 500, "rw");

	int ret = cpp_run(cpp, i, stdout, "stdin");

	printf("rc: %d\n", ret);
	
	cpp_free(cpp);
	return !ret;
}

