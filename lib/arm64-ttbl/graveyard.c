static uint64_t get_oa(struct ARMConfig *cfg, uint64_t block, int level) {
	// For block descriptor only
	uint64_t oa_size = get_oa_size(cfg);
	enum GranuleSize gsize = get_granule_size(cfg);

	// D8.3.2 Block descriptor and Page descriptor formats
	uint64_t bit_high = 0;
	if (oa_size == 52 && (gsize == GRANULE_4KB || gsize == GRANULE_16KB)) {
		bit_high = 49;
	} else {
		bit_high = 47;
	}

	uint64_t bit_low = 0;
	if (oa_size == 52 && gsize == GRANULE_64KB) {
		// For the 4KB granule size, the level 0 descriptor n is 39, the level 1 descriptor n is 30, and the level 2 descriptor n is 21.
		// For the 16KB granule size, the level 1 descriptor n is 36, and the level 2 descriptor n is 25.
		// For the 64KB granule size, the level 1 descriptor n is 42, and the level 2 descriptor n is 29.
		if (gsize == GRANULE_4KB && level == 0) bit_low = 39;
		if (gsize == GRANULE_4KB && level == 1) bit_low = 30;
		if (gsize == GRANULE_4KB && level == 2) bit_low = 21;
		if (gsize == GRANULE_16KB && level == 1) bit_low = 36;
		if (gsize == GRANULE_16KB && level == 2) bit_low = 25;
		if (gsize == GRANULE_64KB && level == 1) bit_low = 42;
		if (gsize == GRANULE_64KB && level == 2) bit_low = 29;
	} else if (oa_size == 48) {
		// For the 4KB granule size, the level 1 descriptor n is 30, and the level 2 descriptor n is 21.
		// For the 16KB granule size, the level 2 descriptor n is 25.
		// For the 64KB granule size, the level 2 descriptor n is 29.
		if (gsize == GRANULE_4KB && level == 1) bit_low = 30;
		if (gsize == GRANULE_4KB && level == 2) bit_low = 21;
		if (gsize == GRANULE_16KB && level == 2) bit_low = 25;
		if (gsize == GRANULE_64KB && level == 2) bit_low = 29;
	} else {
		printf("Unsupported output address: %ld\n", oa_size);
		abort();
	}

	uint64_t mask = (((uint64_t) (bit_high < 64)) << (bit_high & 63)) - 1U;

	printf("%lx\n", block & mask);

	uint64_t oa = ((block & mask) >> bit_low) << bit_low;
	return oa;
}
