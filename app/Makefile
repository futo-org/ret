include cross.mk

CFLAGS := -I../keystone/include
LDFLAGS := -L/usr/local/lib/ -lkeystone

OBJ := re.o libui.o buffers.o parser.o
OBJ := $(call convert_target,$(OBJ))

ifeq ($(TARGET),w)

endif

ifeq ($(TARGET),l)
CFLAGS += $(shell pkg-config --cflags lua5.3 gtk+-3.0)
LDFLAGS += $(shell pkg-config --libs lua5.3 gtk+-3.0) -lui
endif

ret.out: $(OBJ) /usr/lib/ui_scintilla.a
	$(CXX) $(OBJ) /usr/lib/ui_scintilla.a $(LDFLAGS) -o ret.out

LIB_FILES += $(LIBLUA_A) $(LIBUI_A) /usr/x86_64-w64-mingw32/lib/libkeystone.a /usr/$(ARCH)-w64-mingw32/lib/ui_scintilla.a
WIN_LIBS += $(WIN_LINK_ESSENTIALS) -lstdc++ -lgcc -pthread -limm32
ret.exe: $(OBJ) $(LIB_FILES) assets/app.res
	$(CPP) -static $(OBJ) $(LIB_FILES) $(WIN_LIBS) assets/app.res -o ret.exe

clean:
	rm -rf *.out *.o *.elf *.d *.exe assets/*.res
