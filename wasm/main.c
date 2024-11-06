#include <stdio.h>
#include <string.h>

#include <keystone/keystone.h>

static int test_ks(ks_arch arch, int mode, const char *assembly, int syntax)
{
    ks_engine *ks;
    ks_err err;
    size_t count;
    unsigned char *encode;
    size_t size;

    err = ks_open(arch, mode, &ks);
    if (err != KS_ERR_OK) {
        printf("ERROR: failed on ks_open(), quit\n");
        return -1;
    }

    if (syntax)
        ks_option(ks, KS_OPT_SYNTAX, syntax);

    if (ks_asm(ks, assembly, 0, &encode, &size, &count)) {
        printf("ERROR: failed on ks_asm() with count = %lu, error code = %u\n", count, ks_errno(ks));
    } else {
        size_t i;

        printf("%s = ", assembly);
        for (i = 0; i < size; i++) {
            printf("%02x ", encode[i]);
        }
        printf("\n");
        printf("Assembled: %lu bytes, %lu statements\n\n", size, count);
    }

    // NOTE: free encode after usage to avoid leaking memory
    ks_free(encode);

    // close Keystone instance when done
    ks_close(ks);

    return 0;
}

int main(void) {
	puts("Hello, World");

	test_ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, "ldr w1, [sp, #0x8]", 0);
}
