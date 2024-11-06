struct ReTool {
	
};

enum Arch {
	ARCH_ARM,
	ARCH_X86,
	ARCH_X86_64,
	ARCH_ARM64,
};

// Frontend methods
int re_clear_code_editor(struct ReTool *re);
int re_append_code_editor(struct ReTool *re, const char *text);
int re_clear_hex_editor(struct ReTool *re);
int re_append_hex_editor(struct ReTool *re, const char *text);
int re_clear_log(struct ReTool *re);
int re_append_log(struct ReTool *re, const char *text);

int re_assemble(struct ReTool *re, const char *input);
int re_disassemble(struct ReTool *re, const char *input);
int re_format_hex(struct ReTool *re, const char *input);
int re_save_hex(struct ReTool *re, const char *input);
int re_export_c_bytes(struct ReTool *re, const char *input);
