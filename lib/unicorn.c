#include <stdio.h>
#include <stdint.h>
#include <unicorn/unicorn.h>
#include <unicorn/arm.h>

#define MEMORY_BASE_ADDR 0x0
#define RAM_SIZE (1024 * 1024)

#define FRAMEBUFFER_WIDTH 640
#define FRAMEBUFFER_HEIGHT 480
#define FRAMEBUFFER_ADDR 0xf0000000
#define FRAMEBUFFER_SIZE (FRAMEBUFFER_WIDTH * FRAMEBUFFER_HEIGHT * 4)

uint8_t already_dumped = 0;
void barf(uc_engine *uc) {
	int reg;
	uc_reg_read(uc, UC_ARM_REG_PC, &reg);
	printf("PC: %08X\n", reg);

	for (int i = 0; i < 10; i++) {
		uc_reg_read(uc, UC_ARM_REG_R0 + i, &reg);
		printf("r%d: 0x%X\n", i, reg);
	}
}

void io_mmio_writes(uc_engine *uc, uint64_t offset, unsigned size, uint64_t value, void *user_data) {
}

uint64_t io_mmio_reads(uc_engine *uc, uint64_t offset, unsigned size, void *user_data) {
	return 0x0;
}

void fb_mmio_writes(uc_engine *uc, uint64_t offset, unsigned size, uint64_t value, void *user_data) {
}

int emulator(char *filename) {
	uc_engine *uc;
	uc_err err;

	err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
	if (err != UC_ERR_OK) {
		printf("Failed\n");
		return 1;
	}

	// Map dedicated RAM
	err = uc_mem_map(uc, MEMORY_BASE_ADDR, RAM_SIZE, UC_PROT_ALL);
	if (err != UC_ERR_OK) {
		printf("Failed to map memory\n");
		return 1;
	}

	// 100k of stack (grows backwards)
	unsigned int reg = MEMORY_BASE_ADDR + RAM_SIZE;
	reg -= (reg % 0x8);
	uc_reg_write(uc, UC_ARM_REG_SP, &reg);

	FILE *f = fopen(filename, "rb");
	if (f == NULL) {
		printf("Can't open %s\n", filename);
		return 1;
	}

	fseek(f, 0, SEEK_END);
	int length = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *buffer = malloc(length);
	int rc = fread(buffer, length, 1, f);
	if (rc == 0) {
		return 1;
	}
	fclose(f);

	err = uc_mem_write(uc, MEMORY_BASE_ADDR, buffer, length);
	free(buffer);
	if (err != UC_ERR_OK) {
		printf("Failed to write data\n");
		return 1;
	}

	err = uc_mmio_map(uc, FRAMEBUFFER_ADDR, FRAMEBUFFER_SIZE, NULL, NULL, fb_mmio_writes, NULL);
	if (err != UC_ERR_OK) {
		puts("MMIO map error");
		return 1;
	}

	// err = uc_mmio_map(uc, ROCKCHIP_IO_START, ROCKCHIP_IO_SIZE, io_mmio_reads, NULL, io_mmio_writes, NULL);
	// if (err != UC_ERR_OK) {
	// 	puts("MMIO map error");
	// 	return 1;
	// }

	err = uc_emu_start(uc, MEMORY_BASE_ADDR, MEMORY_BASE_ADDR + RAM_SIZE, 1000, 0);
	if (err) {
		printf("Emulation failed: %u %s\n", err, uc_strerror(err));
		barf(uc);
	} else {
		barf(uc);
		puts("Success");
	}
	
	uc_close(uc);

	return 0;
}
