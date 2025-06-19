#include <stdio.h>
#include <stdint.h>
#include <unicorn/unicorn.h>
#include <unicorn/arm.h>
#include "re.h"

#define INSTRUCTION_HARD_CAP 100000

#define MEMORY_BASE_ADDR 0x0
#define RAM_SIZE (1024 * 1024)

#define FRAMEBUFFER_WIDTH 640
#define FRAMEBUFFER_HEIGHT 480
#define FRAMEBUFFER_ADDR 0xf0000000
#define FRAMEBUFFER_SIZE (FRAMEBUFFER_WIDTH * FRAMEBUFFER_HEIGHT * 4)

struct EmulatorState {
	enum Arch arch;
};

uint8_t already_dumped = 0;
void barf(uc_engine *uc) {
	int reg;
	uc_reg_read(uc, UC_ARM64_REG_PC, &reg);
	printf("PC: %08X\n", reg);

	for (int i = 0; i < 10; i++) {
		uc_reg_read(uc, UC_ARM64_REG_X0 + i, &reg);
		printf("r%d: 0x%X\n", i, reg);
	}
}

void pl011_mmio_writes(uc_engine *uc, uint64_t offset, unsigned size, uint64_t value, void *user_data) {
	printf("Write %x to %lu\n", (uint32_t)value, offset);
}

uint64_t pl011_mmio_reads(uc_engine *uc, uint64_t offset, unsigned size, void *user_data) {
	return 0x0;
}

void fb_mmio_writes(uc_engine *uc, uint64_t offset, unsigned size, uint64_t value, void *user_data) {
}

int start_vm(void) {
	uc_engine *uc;
	uc_err err;

	char export[] = {0x60, 0x24, 0x80, 0xd2, };

	err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
	//uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return -1;
    }

	uc_mem_map(uc, 0x0, 0x30000, UC_PROT_ALL);
	uc_mem_write(uc, 0x0, export, sizeof(export));

    err = uc_emu_start(uc, 0x0, 0x0 + 4, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    uint64_t x0 = 0;
    uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
    printf("x0: %lx\n", x0);
	return 0;
}

static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data) {
	printf("Interrupt\n");
}

int re_emulator(enum Arch arch, unsigned int base_addr, struct OutBuffer *asm_buffer, struct OutBuffer *log) {
	log->clear(log);
	uc_engine *uc;
	uc_err err;

	uc_arch _uc_arch = 0;
	uc_mode _uc_mode = 0;
	if (arch == ARCH_X86_64) {
		_uc_arch = UC_ARCH_X86;
		_uc_mode |= UC_MODE_64;
	} else if (arch == ARCH_ARM64) {
		_uc_arch = UC_ARCH_ARM64;
		_uc_mode |= UC_MODE_ARM;
	} else if (arch == ARCH_ARM32) {
		_uc_arch = UC_ARCH_ARM64;
		_uc_mode |= UC_MODE_32 | UC_MODE_ARM;
	} else {
		log->append(log, "Unknown architecture", 0);
		//printf("Unknown architecture %d\n", arch);
		return -1;
	}

	err = uc_open(_uc_arch, _uc_mode, &uc);
	if (err != UC_ERR_OK) {
		log->append(log, "Failed to setup emulator", 0);
		//printf("Failed to setup emulator\n");
		return -1;
	}

	// Map dedicated RAM
	err = uc_mem_map(uc, MEMORY_BASE_ADDR, RAM_SIZE, UC_PROT_ALL);
	if (err != UC_ERR_OK) {
		log->append(log, "Failed to map memory", 0);
		//printf("Failed to map memory\n");
		return -1;
	}

	// 100k of stack (grows backwards)
	unsigned int reg = MEMORY_BASE_ADDR + RAM_SIZE;
	reg -= (reg % 0x8);
	uc_reg_write(uc, UC_ARM_REG_SP, &reg);

	err = uc_mem_write(uc, MEMORY_BASE_ADDR, asm_buffer->buffer, asm_buffer->offset);
	if (err != UC_ERR_OK) {
		log->append(log, "Failed to write data", 0);
		//printf("Failed to write data\n");
		return -1;
	}

//	err = uc_mmio_map(uc, FRAMEBUFFER_ADDR, FRAMEBUFFER_SIZE, NULL, NULL, fb_mmio_writes, NULL);
//	if (err != UC_ERR_OK) {
//		puts("MMIO map error");
//		return 1;
//	}

	err = uc_mmio_map(uc, 0x9000000, 0x1000, pl011_mmio_reads, NULL, pl011_mmio_writes, NULL);
	if (err != UC_ERR_OK) {
		log->append(log, "MMIO map error", 0);
		return 1;
	}

	uc_hook trace;
	err = uc_hook_add(uc, &trace, UC_HOOK_INTR, hook_intr, NULL, 1, 0, 0);

	err = uc_emu_start(uc, MEMORY_BASE_ADDR, MEMORY_BASE_ADDR + asm_buffer->offset, 0, INSTRUCTION_HARD_CAP);
	if (err) {
		log->append(log, "Emulation failed", 0);
		printf("Emulation failed: %u %s\n", err, uc_strerror(err));
		barf(uc);
	} else {
		barf(uc);
		log->append(log, "Emulation success", 0);
		puts("Success");
	}
	
	uc_close(uc);

	return 0;
}
