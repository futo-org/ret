# Cross-compilation stubs for GNU make
# w: Windows
# l: Linux
# m: Mac
help:
	@echo "valid values for TARGET: w, l, m"

ifndef TARGET
$(warning TARGET not defined, assuming Linux)
TARGET := l
endif

ARCH := x86_64

ifeq ($(TARGET),w)
MINGW := x86_64-w64-mingw32
CC := $(MINGW)-gcc
CPP := $(MINGW)-c++

LIBWPD_A := /usr/$(ARCH)-w64-mingw32/lib/libwpd.a
LIBLUA_A := /usr/$(ARCH)-w64-mingw32/lib/liblua.a
LIBUI_DLL := /usr/$(ARCH)-w64-mingw32/lib/libui_win64.dll
LIBUI_A := /usr/$(ARCH)-w64-mingw32/lib/libui.a

WIN_LINK_ESSENTIALS += -luser32 -lkernel32 -lgdi32 -lcomctl32 -luxtheme -lmsimg32 -lcomdlg32 -ld2d1 -ldwrite -lole32 -loleaut32 -loleacc -lssp -lurlmon -luuid -lws2_32

%.res: %.rc
	$(MINGW)-windres $< -O coff -o $@
endif

ifeq ($(TARGET),l)
# Create appimages
# TODO: Link to linuxdeploy and appimagetool
define create_appimage
linuxdeploy --appdir=AppDir --executable=$1.out -d assets/$1.desktop -i assets/$1.png
appimagetool AppDir
endef

endif

# Convert object list to $(TARGET).o
# eg: x.o a.o -> x.w.o a.w.o if $(TARGET) is w
define convert_target
$(patsubst %.o,%.$(TARGET).o,$1)
endef

%.$(TARGET).o: %.c
	$(CC) -MMD -c $< $(CFLAGS) -o $@

%.$(TARGET).o: %.cpp
	$(CC) -MMD -c $< $(CFLAGS) -o $@

%.$(TARGET).o: %.S
	$(CC) -c $< $(CFLAGS) -o $@
