include cross.mk

CFLAGS := -I../keystone/include $(shell pkg-config --cflags lua5.3)
LDFLAGS := -L/usr/local/lib/ -lkeystone $(shell pkg-config --libs lua5.3) -lui

OBJ := re.o libui.o buffers.o parser.o
OBJ := $(call convert_target,$(OBJ))

ret.out: $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) -o ret

WIN_LIBS += $(LIBLUA_A) $(LIBUI_DLL)
WIN_LIBS += $(WIN_LINK_ESSENTIALS) -lstdc++ -lgcc -lpthread
ret.exe: $(OBJ) assets/app.res
	$(CC) $(OBJ) /usr/x86_64-w64-mingw32/lib/libkeystone.a $(WIN_LIBS) assets/app.res -o ret.exe

clean:
	rm -rf *.out *.o *.elf *.d *.exe assets/*.res
