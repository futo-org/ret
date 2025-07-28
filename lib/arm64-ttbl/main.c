// ARM64 translation table dumper
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

inline static int read_u32(const void *buf, uint32_t *out) {
	const uint8_t *b = (const uint8_t *)buf;
	*out = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
	return 4;
}

struct BlockDescriptor {
	uint64_t output_address;
	uint64_t size;
	uint32_t upper_attributes;
	uint32_t lower_attributes;

	uint32_t is_combined;
	uint64_t block;
};

struct ARMConfig {
	/// Base physical address of the CPU
	uint64_t base_address;
	uint64_t ttbr0_elx;
	uint64_t tcr_elx;
	uint64_t mair_elx;

	int exception_level;

	/// Internal buffer base offset for the get_memory function to use
	uint32_t buffer_base;
	void *priv;
	int (*get_memory)(struct ARMConfig *cfg, uint8_t *buffer, uint64_t offset, uint32_t size);

	// Number of blocks counted in ttbl
	int block_n;

	// Invalid if block_n == 0
	struct BlockDescriptor last_block;

	// Combined size of consecutive identical blocks that start and end in the same address
	uint64_t current_combined_size;
	// Start address of the combined identical blocks
	uint64_t initial_common_address;
};

enum GranuleSize {
	GRANULE_4KB,
	GRANULE_16KB,
	GRANULE_64KB,
};

static enum GranuleSize get_granule_size(struct ARMConfig *cfg) {
	uint32_t tg0 = (cfg->tcr_elx >> 14) & 0b11;
	if (tg0 == 0b00) return GRANULE_4KB;
	if (tg0 == 0b01) return GRANULE_64KB;
	if (tg0 == 0b10) return GRANULE_16KB;
	abort();
}

static int get_oa_size(struct ARMConfig *cfg) {
	// https://developer.arm.com/documentation/ddi0601/2025-06/AArch64-Registers/TCR-EL3--Translation-Control-Register--EL3-
	uint32_t ps = (cfg->tcr_elx >> 16) & 0b111;
	if (ps == 0b000) return 32;
	if (ps == 0b001) return 36;
	if (ps == 0b010) return 40;
	if (ps == 0b011) return 42;
	if (ps == 0b100) return 44;
	if (ps == 0b101) return 48;
	if (ps == 0b110) return 52;
	abort();
}

static uint64_t get_oa(struct ARMConfig *cfg, uint64_t block, int level) {
	// For block descriptor only
	uint64_t oa_size = get_oa_size(cfg);
	enum GranuleSize gsize = get_granule_size(cfg);

	// ARM spec says for all descriptors no bits higher than 47
	// will be used for address
	uint64_t mask = ((1ULL << 48) - 1) & ~((1ULL << 12) - 1);

//	printf("%lx\n", block);

	// TODO: if FEAT_LPA,
	// Block descriptor bits[15:12] are bits[51:48] of the OA

	uint64_t oa = ((block & mask));
	return oa;
}

#define TERRABYTE 0x10000000000ULL
#define GIGABYTE 0x40000000ULL
#define MEGABYTE 0x100000ULL
#define KILOBYTE 0x400ULL
static uint64_t get_block_size(struct ARMConfig *cfg, int level) {
	// https://developer.arm.com/documentation/101811/0104/Translation-granule
	switch (get_granule_size(cfg)) {
	case GRANULE_4KB:
		if (level == 0) return GIGABYTE * 512;
		if (level == 1) return GIGABYTE;
		if (level == 2) return MEGABYTE * 2;
		if (level == 3) return KILOBYTE * 4;
		abort();
	case GRANULE_16KB:
		if (level == 0) return TERRABYTE * 128;
		if (level == 1) return GIGABYTE * 64;
		if (level == 2) return MEGABYTE * 32;
		if (level == 3) return KILOBYTE * 16;
		abort();
	case GRANULE_64KB:
		abort();
	}
}

int get_memory_file(struct ARMConfig *cfg, uint8_t *buffer, uint64_t offset, uint32_t size) {
	FILE *f = cfg->priv;

	if (cfg->buffer_base > offset) {
		printf("Data requested below buffer buffer base\n");
		return -1;
	}
	
	fseek(f, offset - cfg->buffer_base - cfg->base_address, SEEK_SET);
	if (fread(buffer, 1, size, f) != size) {
		return -1;
	}
	return 0;
}

int open_from_file(struct ARMConfig *cfg, const char *filename, uint32_t file_base) {
	cfg->priv = fopen(filename, "rb");
	cfg->buffer_base = file_base;
	if (cfg->priv == NULL) {
		printf("File %s not found\n", filename);
		return -1;
	}
	cfg->get_memory = get_memory_file;
	return 0;
}

const char *get_indent_lvl(int level) {
	if (level == 1) return "";
	if (level == 2) return "  ";
	if (level == 4) return "    ";
	if (level == 5) return "      ";
	return "";
}

struct MemorySection {
	uint32_t upper_attributes;
	uint32_t lower_attributes;
	uint64_t base;
	uint64_t size;
};
static void print_section(struct ARMConfig *cfg, int level, struct MemorySection section) {
	printf("0x%lx - 0x%lx (%x)\n", section.base, section.base + section.size,
		section.lower_attributes & 0b111);
}

int walk_level(struct ARMConfig *cfg, uint64_t of, int level) {
	if (level > 3) abort();

	struct BlockDescriptor dummy_block;

	int n_block = 0;
	while (1) {
		// Read the block
		uint8_t buffer[8];
		cfg->get_memory(cfg, buffer, of, sizeof(buffer));
		uint32_t l, h;
		of += read_u32(buffer, &l);
		of += read_u32(buffer + 4, &h);

		uint64_t full_block = ((uint64_t)h << 32) | l;

		// Check valid bit
		if ((l & 1) != 1) {
			if (cfg->block_n == 0) {
				// Didn't get a single valid block
				abort();
			}
			if (cfg->current_combined_size != 0) {
				print_section(cfg, level, (struct MemorySection){
					.upper_attributes = cfg->last_block.upper_attributes,
					.lower_attributes = cfg->last_block.lower_attributes,
					.base = cfg->initial_common_address,
					.size = cfg->current_combined_size,
				});
//				printf("%sCombined blocks 0x%lx - 0x%lx\n", get_indent_lvl(level), cfg->initial_common_address, cfg->initial_common_address + cfg->current_combined_size);
				cfg->current_combined_size = 0;
			}
//			printf("%sInvalid block (0x%lx) at 0x%lx\n", get_indent_lvl(level), full_block, of);
			break;
		}

		uint64_t output_address = get_oa(cfg, full_block, level);

		// For lookup levels other than lookup level 3, one of the following:
		// - If bit[1] is 0, then the descriptor is a Block descriptor.
		// - If bit[1] is 1, then the descriptor is a Table descriptor.
		// For lookup level 3, one of the following:
		// - If bit[1] is 0, then the descriptor is reserved, and treated as invalid.
		// - If bit[1] is 1, then the descriptor is a Page descriptor.
		if ((l & (1 << 1)) == 0) {
			struct BlockDescriptor block = {
				.output_address = output_address,
				.size = get_block_size(cfg, level),
				.block = full_block,
				.upper_attributes = full_block >> 47,
				.lower_attributes = full_block & 0xfff,
			};

			// Block descriptor
			// temporary hack to compute address in this descriptor
			if (cfg->block_n != 0) {
				uint64_t last_block_end = cfg->last_block.output_address + cfg->last_block.size;

				int blocks_align = last_block_end == block.output_address;
				int attrs_same = (block.upper_attributes == cfg->last_block.upper_attributes)
					&& (block.lower_attributes == cfg->last_block.lower_attributes);

				if (blocks_align && attrs_same) {
					if (cfg->current_combined_size == 0) {
						cfg->initial_common_address = cfg->last_block.output_address;
					}
					cfg->current_combined_size += cfg->last_block.size + block.size;
				} else {
					if (cfg->current_combined_size != 0) {
						print_section(cfg, level, (struct MemorySection){
							.upper_attributes = cfg->last_block.upper_attributes,
							.lower_attributes = cfg->last_block.lower_attributes,
							.base = cfg->initial_common_address,
							.size = cfg->current_combined_size,
						});
//						printf("%sCombined blocks 0x%lx - 0x%lx\n", get_indent_lvl(level), cfg->initial_common_address, cfg->initial_common_address + cfg->current_combined_size);
						cfg->current_combined_size = 0;
					}

//					print_section(cfg, level, (struct MemorySection){
//						.upper_attributes = block.upper_attributes,
//						.lower_attributes = block.lower_attributes,
//						.base = block.output_address,
//						.size = block.size,
//					});

//					printf("%sBlock descriptor -> 0x%lx\n", get_indent_lvl(level), block.output_address);
//					printf("%sDescriptor is at 0x%lx\n", get_indent_lvl(level), of);
				}
			} else {
				print_section(cfg, level, (struct MemorySection){
					.upper_attributes = block.upper_attributes,
					.lower_attributes = block.lower_attributes,
					.base = block.output_address,
					.size = block.size,
				});
//				printf("%sBlock descriptor -> 0x%lx\n", get_indent_lvl(level), output_address);
//				printf("%sDescriptor is at 0x%lx\n", get_indent_lvl(level), of);
			}

			cfg->last_block = block;
			cfg->block_n++;
		} else {
//			printf("Page descriptor pointing to 0x%lx\n", output_address);
			int rc = walk_level(cfg, output_address, level + 1); // Recurse
			if (rc) return rc;
		}
	}

	return 0;
}

int walk_tt(struct ARMConfig *cfg) {
	return walk_level(cfg, cfg->ttbr0_elx, 1);
}

int main(void) {
	// Dummy
	struct ARMConfig cfg = {0};
	cfg.ttbr0_elx = 0xefff0000;
	cfg.mair_elx = 0xff440c0400;
	cfg.tcr_elx = 0x8081351c;
	if (open_from_file(&cfg, "ram.img", 0xefff0000)) return -1;	
	walk_tt(&cfg);

	return 0;
}
