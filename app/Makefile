include cross.mk

CFLAGS := -I../keystone/include $(shell pkg-config --cflags lua5.3)
LDFLAGS := -L/usr/local/lib/ -lkeystone $(shell pkg-config --libs lua5.3) -lui

OBJ := re.o libui.o buffers.o parser.o
OBJ := $(call convert_target,$(OBJ))

ret.out: $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) -o ret

LIB_FILES += $(LIBLUA_A) $(LIBUI_A) /usr/x86_64-w64-mingw32/lib/libkeystone.a /usr/$(ARCH)-w64-mingw32/lib/ui_scintilla.a
WIN_LIBS += $(WIN_LINK_ESSENTIALS) -lstdc++ -lgcc -pthread -limm32
ret.exe: $(OBJ) $(LIB_FILES) assets/app.res
	$(CPP) -static $(OBJ) $(LIB_FILES) $(WIN_LIBS) assets/app.res -o ret.exe

clean:
	rm -rf *.out *.o *.elf *.d *.exe assets/*.res
