#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ui.h>
#include <lualib.h>
#include <lauxlib.h>
#include <lua.h>
#include <ui/ui_scintilla.h>
#include "re.h"
#include "sci.h"

const char *demo_arm64 =
"b skip\n"
"string:\n"
".ascii \"Hello, World\\n\"\n"
".byte 0\n"
".align 4\n"
"skip:\n"
"\n"
"adr x1, string\n"
"top:\n"
"	ldrb w0, [x1]\n"
"	cmp w0, #0x0\n"
"	beq end\n"
"	svc #0x0\n"
"	add x1, x1, #0x1\n"
"	b top\n"
"end:\n";

struct App {
	struct ReTool *re;
	uiWindow *main;
	uiScintilla *code;
	uiScintilla *hex;
	struct OutBuffer log;
};

static void editor_clear(struct OutBuffer *buf) {
	uiScintillaSetText(buf->handle, "");
}
static void editor_append_u8(struct OutBuffer *buf, const void *in, int len) {
	for (int i = 0; i < len; i++) {
		if ((buf->length & 0b11) == 0 && buf->length != 0) {
			uiScintillaAppend(buf->handle, "\n");
		}

		char buffer[16];
		sprintf(buffer, "%02x ", ((uint8_t *)in)[i]);

		uiScintillaAppend(buf->handle, buffer);

		buf->length++;
	}
}
static void editor_append_u32(struct OutBuffer *buf, const void *in, int len) {
	for (int i = 0; i < len; i++) {
		char buffer[16];
		sprintf(buffer, "%04x\n", ((uint8_t *)in)[i]);
		uiScintillaAppend(buf->handle, buffer);
	}
}
static void editor_append_string(struct OutBuffer *buf, const void *in, int len) {
	uiScintillaAppend(buf->handle, (const char *)in);
}

extern int luaopen_libuilua(lua_State *L);

static void openClicked(uiMenuItem *item, uiWindow *w, void *data) {
	char *filename = uiOpenFile(w);
	if (filename == NULL) {
		uiMsgBoxError(w, "No file selected", "Don't be alarmed!");
		return;
	}
	uiMsgBox(w, "File selected", filename);
	uiFreeText(filename);
}

static void saveClicked(uiMenuItem *item, uiWindow *w, void *data) {
	char *filename = uiSaveFile(w);
	if (filename == NULL) {
		uiMsgBoxError(w, "No file selected", "Don't be alarmed!");
		return;
	}
	uiMsgBox(w, "File selected (don't worry, it's still there)", filename);
	uiFreeText(filename);
}

static int onClosing(uiWindow *w, void *data) {
	printf("Goodbye\n");
	uiQuit();
	return 1;
}

static int onShouldQuit(void *data)
{
	uiWindow *mainwin = uiWindow(data);
	uiControlDestroy(uiControl(mainwin));
	return 1;
}

static void run_script_clicked(uiMenuItem *item, uiWindow *w, void *data) {

}

void btn_onclick_asm(uiButton *b, void *data) {
	struct App *app = data;
	char *s = uiScintillaText(app->code);

	struct OutBuffer buf;
	buf.length = 0;
	buf.handle = app->hex;
	buf.append = editor_append_u8;
	buf.clear = editor_clear;

	re_asm(app->re, &buf, &app->log, s);
}

static void prettify(struct App *app, int size) {
	char *s = uiScintillaText(app->hex);
	struct OutBuffer buf;
	buf.length = 0;
	buf.handle = app->hex;
	if (size == 1) {
		buf.append = editor_append_u8;
	} else {
		buf.append = editor_append_u32;
	}
	buf.clear = editor_clear;
	prettify_hex(app->re, &buf, s);
}

static void set_arch(struct App *app, enum Arch arch) {
	char *arch_s;
	switch (arch) {
	case ARCH_ARM64:
		arch_s = "AARCH64";
		break;
	case ARCH_X86_64:
		arch_s = "X86_64";
		break;
	case ARCH_ARM: abort();
	case ARCH_X86: abort();
	}

	char buffer[64];
	sprintf(buffer, "Ret V4 - %s", arch_s);
	uiWindowSetTitle(app->main, buffer);

	app->re->arch = arch;
}

void item_onclick_prettify_u8(uiMenuItem *i, uiWindow *w, void *data) {
	prettify(data, 1);
}
void item_onclick_prettify_u32(uiMenuItem *i, uiWindow *w, void *data) {
	prettify(data, 1);
}
void arch_switch_arm64(uiMenuItem *i, uiWindow *w, void *data) {
	set_arch(data, ARCH_ARM64);
}
void arch_switch_x86_64(uiMenuItem *i, uiWindow *w, void *data) {
	set_arch(data, ARCH_X86_64);
}

void config_editor(uiScintilla *e) {
	uiScintillaSendMessage(e, SCI_SETVIEWWS, SCWS_INVISIBLE, 0);
	uiScintillaSendMessage(e, SCI_SETELEMENTCOLOUR, SC_ELEMENT_CARET, 0xffffffff);
	uiScintillaSendMessage(e, SCI_SETELEMENTCOLOUR, SC_ELEMENT_WHITE_SPACE_BACK, 0x0);
	uiScintillaSendMessage(e, SCI_STYLESETBACK, STYLE_DEFAULT, 0x080808);
//	uiScintillaSendMessage(e, SCI_SETELEMENTCOLOUR, SC_ELEMENT_WHITE_SPACE, 0x0);
	uiScintillaSendMessage(e, SCI_STYLESETFORE, STYLE_DEFAULT, 0xffffff);

	uiScintillaSendMessage(e, SCI_SETELEMENTCOLOUR, SC_ELEMENT_SELECTION_BACK, 0xffaaaaaa);
	uiScintillaSendMessage(e, SCI_SETELEMENTCOLOUR, SC_ELEMENT_SELECTION_TEXT, 0xff000000);

#ifdef WIN32
uiScintillaSendMessage(e, SCI_STYLESETFONT, STYLE_DEFAULT, (uintptr_t)"FreeMono");
#else
	uiScintillaSendMessage(e, SCI_STYLESETFONT, STYLE_DEFAULT, (uintptr_t)"Monospace");
#endif

	uiScintillaSendMessage(e, SCI_STYLECLEARALL, 0, 0);
	uiScintillaSendMessage(e, SCI_SETTABWIDTH, 4, 0);

	uiScintillaSendMessage(e, SCI_SETMARGINMASKN, 0, 0);
	uiScintillaSendMessage(e, SCI_STYLESETFORE, STYLE_LINENUMBER, 0xeeeeee);
	uiScintillaSendMessage(e, SCI_STYLESETBACK, STYLE_LINENUMBER, 0x262626);
	uiScintillaSendMessage(e, SCI_SETMARGINTYPEN, 0, SC_MARGIN_NUMBER);
	uiScintillaSendMessage(e, SCI_SETMARGINWIDTHN, 0, 30);
}

int ret_entry_ui(struct ReTool *re) {
	struct App app;
	app.re = re;

#ifdef _WIN32
	// Redirect stdout
	AttachConsole(-1);
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);
#endif

	uiInitOptions o = {0};
	const char *err;

	err = uiInit(&o);
	if (err != NULL) {
		fprintf(stderr, "Error initializing libui-ng: %s\n", err);
		uiFreeInitError(err);
		return 1;
	}

	uiMenu *menu;
	uiMenuItem *item;

	menu = uiNewMenu("File");
	item = uiMenuAppendItem(menu, "Open");
	item = uiMenuAppendItem(menu, "Save");
	item = uiMenuAppendItem(menu, "Export workspace");
	item = uiMenuAppendQuitItem(menu);

	menu = uiNewMenu("Assembly");
 	item = uiMenuAppendItem(menu, "Assemble");
 	item = uiMenuAppendItem(menu, "Settings");

	menu = uiNewMenu("Hex");
	item = uiMenuAppendItem(menu, "Export as file");
	item = uiMenuAppendItem(menu, "Convert to C");
	item = uiMenuAppendItem(menu, "Prettify as u8");
	uiMenuItemOnClicked(item, item_onclick_prettify_u8, &app);
	item = uiMenuAppendItem(menu, "Prettify as u32");
	uiMenuItemOnClicked(item, item_onclick_prettify_u32, &app);
	item = uiMenuAppendItem(menu, "Parse as base10");
	item = uiMenuAppendItem(menu, "Settings");

	menu = uiNewMenu("Architecture");
	item = uiMenuAppendItem(menu, "Switch to X86_64");
	uiMenuItemOnClicked(item, arch_switch_x86_64, &app);
	item = uiMenuAppendItem(menu, "Switch to AARCH64");
	uiMenuItemOnClicked(item, arch_switch_arm64, &app);
	item = uiMenuAppendItem(menu, "Switch to ARM");

	menu = uiNewMenu("Help");
	item = uiMenuAppendItem(menu, "Help");
	item = uiMenuAppendAboutItem(menu);

	app.main = uiNewWindow("Ret V4 - ARM64", 1300, 1000, 1);

	uiWindowSetMargined(app.main, 0);
	uiWindowOnClosing(app.main, onClosing, NULL);
	uiOnShouldQuit(onShouldQuit, app.main);

	uiBox *main_box = uiNewVerticalBox();
	uiBoxSetPadded(main_box, 0);

	// Code panels
	uiBox *hbox = uiNewHorizontalBox();
	{
		uiBoxSetPadded(hbox, 0);
	
		app.code = uiNewScintilla();
		uiBoxAppend(hbox, uiControl(app.code), 1);
		config_editor(app.code);
		uiScintillaSetText(app.code, demo_arm64);
	
		uiBox *vbox = uiNewVerticalBox();
	
		app.hex = uiNewScintilla();
		uiBoxAppend(vbox, (uiControl *)app.hex, 1);
		config_editor(app.hex);
		uiScintillaSetText(app.hex, "00 00 00 00");
	
		uiScintilla *log = uiNewScintilla();
		config_editor(log);
		app.log.length = 0;
		app.log.handle = log;
		app.log.append = editor_append_string;
		app.log.clear = editor_clear;

		uiBoxAppend(vbox, (uiControl *)log, 1);
		app.log.append(&app.log, "RET v4 (Reverse-Engineering Tool)\n", 0);
		app.log.append(&app.log, "Logs go here.\n", 0);
	
		uiBoxAppend(hbox, uiControl(vbox), 1);
	}

	// Top bar
	uiBox *bar = uiNewHorizontalBox();
	{
		uiBoxSetPadded(bar, 1);
		uiButton *button = uiNewButton("Assemble");
		uiButtonOnClicked(button, btn_onclick_asm, &app);
		uiBoxAppend(bar, uiControl(button), 0);
		uiBoxAppend(bar, uiControl(uiNewButton("Disassemble")), 0);
		uiBoxAppend(bar, uiControl(uiNewButton("Execute")), 0);
		uiBoxAppend(bar, uiControl(uiNewButton("Assemble + Execute")), 0);
		uiBoxAppend(bar, uiControl(uiNewHorizontalSeparator()), 1);
		uiBoxAppend(bar, uiControl(uiNewLabel("Base address: ")), 0);
		uiEntry *entry = uiNewEntry();
		uiEntrySetText(entry, "0x0");
		uiBoxAppend(bar, uiControl(entry), 0);
	}

	uiBoxAppend(main_box, uiControl(bar), 0);
	uiBoxAppend(main_box, uiControl(hbox), 1);

	uiWindowSetChild(app.main, uiControl(main_box));
	uiControlShow(uiControl(app.main));

	uiMain();
	uiUninit();

	return 0;
}
