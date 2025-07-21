// ARM64 translation table dumper
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

inline static int read_u32(const void *buf, uint32_t *out) {
	const uint8_t *b = (const uint8_t *)buf;
	*out = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
	return 4;
}

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
};

enum GranuleSize {
	GRANULE_4KB,
	GRANULE_16KB,
	GRANULE_64KB,
};

struct BlockDescriptor {
	uint32_t upper_attributes;
	uint32_t lower_attributes;
	uint64_t output_address;
};

static enum GranuleSize get_granule_size(struct ARMConfig *cfg) {
	uint32_t tg0 = (cfg->tcr_elx >> 14) & 0b11;
	if (tg0 == 0b00) return GRANULE_4KB;
	if (tg0 == 0b01) return GRANULE_64KB;
	if (tg0 == 0b10) return GRANULE_16KB;
	abort();
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

int walk_level(struct ARMConfig *cfg, uint64_t of, int level) {
	unsigned int last_addr = 0;
	unsigned int last_block_size = 0;
	// Number of common identical entries in a row
	unsigned int common_entries = 0;

	while (1) {
		// Read the block
		uint8_t buffer[8];
		cfg->get_memory(cfg, buffer, of, sizeof(buffer));
		uint32_t l, h;
		of += read_u32(buffer, &l);
		of += read_u32(buffer + 4, &h);
		uint64_t block = ((uint64_t)h << 32) & l;

		// Check valid bit
		if ((l & 1) != 1) {
			if (common_entries != 0) {
				printf("%s%d common entries of size 0x%x\n", get_indent_lvl(level), common_entries, last_block_size);
				common_entries = 0;
			}

			printf("%sInvalid block (0x%lx) at 0x%lx\n", get_indent_lvl(level), block, of);

			break;
		}

		// if 1:1 is 0, then we have a block descriptor
		if ((l & (1 << 1)) == 0) {
			// temporary hack to compute address in this descriptor
			uint32_t oa_addr_n = 0xa;
			uint32_t oa_addr_mask = 0xffffffff;
			uint32_t addr = l & (oa_addr_mask << oa_addr_n);
			if (last_addr != 0x0) {
				uint32_t block_size = addr - last_addr;
				if (block_size == last_block_size) {
					// TODO: Check attributes to make sure the blocks are identical
					common_entries++;
				} else {
					if (common_entries != 0) {
						printf("%s%d common entries of size 0x%x\n", get_indent_lvl(level), common_entries, last_block_size);
						common_entries = 0;
					} else {
						printf("%sBlock descriptor -> 0x%x\n", get_indent_lvl(level), addr);
						printf("%sDescriptor is at 0x%lx\n", get_indent_lvl(level), of);
					}
				}

				last_block_size = block_size;
			}

			last_addr = addr;
		} else {
			// else, this is a table descriptor
			uint32_t oa_addr_n = 0xa;
			uint32_t oa_addr_mask = 0xffffffff;
			uint32_t addr = l & (oa_addr_mask << oa_addr_n);

			printf("Page descriptor pointing to 0x%x\n", addr);

			int rc = walk_level(cfg, addr, level + 1); // Recurse
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
