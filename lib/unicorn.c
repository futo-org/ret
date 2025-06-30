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
	uc_arch arch;
	struct RetBuffer *log;
	char last_char;
};

void pl011_mmio_writes(uc_engine *uc, uint64_t offset, unsigned size, uint64_t value, void *user_data) {
	struct EmulatorState *state = (struct EmulatorState *)user_data;
	switch (offset) {
	case 0x0: {
		char str[2] = {'\0', '\0'};
		str[0] = (char)value;
		state->last_char = (char)value;
		state->log->append(state->log, str, 0);
	} return;
	}
}

uint64_t pl011_mmio_reads(uc_engine *uc, uint64_t offset, unsigned size, void *user_data) {
	struct EmulatorState *state = (struct EmulatorState *)user_data;
	return 0x0;
}

void fb_mmio_writes(uc_engine *uc, uint64_t offset, unsigned size, uint64_t value, void *user_data) {
	struct EmulatorState *state = (struct EmulatorState *)user_data;
}

static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data) {
	printf("Interrupt\n");
}

int re_emulator(enum Arch arch, unsigned int base_addr, struct RetBuffer *asm_buffer, struct RetBuffer *log) {
	if (asm_buffer == NULL) return -1;
	if (log == NULL) return -1;
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
		_uc_arch = UC_ARCH_ARM;
		_uc_mode |= UC_MODE_ARM;
	} else if (arch == ARCH_ARM32_THUMB) {
		_uc_arch = UC_ARCH_ARM;
		_uc_mode |= UC_MODE_THUMB;
	} else {
		buffer_appendf(log, "Unknown architecture\n");
		return -1;
	}

	struct EmulatorState state = {
		.arch = _uc_arch,
		.log = log,
		.last_char = '\n',
	};

	err = uc_open(_uc_arch, _uc_mode, &uc);
	if (err != UC_ERR_OK) {
		buffer_appendf(log, "Failed to setup emulator\n", 0);
		return -1;
	}

	// Map dedicated RAM
	err = uc_mem_map(uc, MEMORY_BASE_ADDR, RAM_SIZE, UC_PROT_ALL);
	if (err != UC_ERR_OK) {
		buffer_appendf(log, "Failed to map memory\n", 0);
		return -1;
	}

	{
		// 100k of stack (grows backwards)
		uint32_t reg = MEMORY_BASE_ADDR + RAM_SIZE;
		reg -= (reg % 0x8);
		if (_uc_arch == UC_ARCH_ARM) {
			uc_reg_write(uc, UC_ARM_REG_SP, &reg);
		}
	}

	err = uc_mem_write(uc, MEMORY_BASE_ADDR, asm_buffer->buffer, asm_buffer->offset);
	if (err != UC_ERR_OK) {
		buffer_appendf(log, "Failed to write data\n", 0);
		return -1;
	}

//	err = uc_mmio_map(uc, FRAMEBUFFER_ADDR, FRAMEBUFFER_SIZE, NULL, NULL, fb_mmio_writes, NULL);
//	if (err != UC_ERR_OK) {
//		puts("MMIO map error");
//		return 1;
//	}

	err = uc_mmio_map(uc, 0x9000000, 0x1000, pl011_mmio_reads, &state, pl011_mmio_writes, &state);
	if (err != UC_ERR_OK) {
		buffer_appendf(log, "MMIO map error\n", 0);
		return 1;
	}

	uc_hook trace;
	err = uc_hook_add(uc, &trace, UC_HOOK_INTR, (void *)hook_intr, &state, 1, 0, 0);
	if (err != UC_ERR_OK) {
		buffer_appendf(log, "hook setup error\n", 0);
		return 1;
	}

	if (_uc_mode & UC_MODE_THUMB) {
		err = uc_emu_start(uc, MEMORY_BASE_ADDR | 1, MEMORY_BASE_ADDR + asm_buffer->offset, 0, INSTRUCTION_HARD_CAP);
	} else {
		err = uc_emu_start(uc, MEMORY_BASE_ADDR, MEMORY_BASE_ADDR + asm_buffer->offset, 0, INSTRUCTION_HARD_CAP);		
	}
	if (state.last_char != '\n') {
		buffer_appendf(log, "\n");
	}
	if (err) {
		buffer_appendf(log, "Emulation failed\n", 0);
		printf("Emulation failed: %u %s\n", err, uc_strerror(err));
	} else {
		buffer_appendf(log, "Emulation finished\n", 0);
	}

	uint8_t rb[16] = {0};
	if (_uc_arch == UC_ARCH_ARM64) {
		int pc_reg = UC_ARM64_REG_PC;
		int x0_reg = UC_ARM64_REG_X0;

		uc_reg_read(uc, pc_reg, rb);
		buffer_appendf(log, " PC: 0x%016llX\n", ((uint64_t *)rb)[0]);
	
		for (int i = 0; i < 5; i++) {
			uc_reg_read(uc, x0_reg + i, rb);
			buffer_appendf(log, " x%d: 0x%016llX\n", i, ((uint64_t *)rb)[0]);
		}
	} else if (_uc_arch == UC_ARCH_X86) {
		uint64_t reg;
		const char *reg_names[] = {"eax", "ebx", "ecx", "esp", "ebp"};
		int regs[] = {UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_ESP, UC_X86_REG_EBP};

		for (int i = 0; i < 5; i++) {
			uc_reg_read(uc, regs[i], &reg);
			buffer_appendf(log, " %s: 0x%X\n", reg_names[i], reg);
		}
	} else if (_uc_arch == UC_ARCH_ARM) {
		uint32_t reg;
		int pc_reg = UC_ARM_REG_PC;
		int x0_reg = UC_ARM_REG_R0;
	
		uc_reg_read(uc, pc_reg, &reg);
		buffer_appendf(log, " PC: 0x%08X\n", reg);
	
		for (int i = 0; i < 5; i++) {
			uc_reg_read(uc, x0_reg + i, &reg);
			buffer_appendf(log, " r%d: 0x%X\n", i, reg);
		}
	}
	
	uc_close(uc);

	return 0;
}

#if 0
int test_vm(void) {
	uc_engine *uc;
	uc_err err;

	char export[] = {0x4f, 0xf0, 0x01, 0x00};
//	char export[] = {0x01, 0x00, 0xa0, 0xe3};

	err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n", err,
               uc_strerror(err));
        return -1;
    }

	uc_mem_map(uc, 0x0, 0x30000, UC_PROT_ALL);
	uc_mem_write(uc, 0x0, export, sizeof(export));

    err = uc_emu_start(uc, 0x0 + 1, 0x0 + 4 - 1, 0, 1000);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    uint64_t x0 = 0;
    uc_reg_read(uc, UC_ARM_REG_R0, &x0);
    printf("x0: %lx\n", x0);
	return 0;
}
#endif
