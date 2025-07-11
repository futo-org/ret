CMAKE ?= /usr/share/emscripten/cmake/Modules/Platform/Emscripten.cmake

debug_build:
	cmake -G Ninja -B build -DCMAKE_TOOLCHAIN_FILE=$(CMAKE) -DSUPPORT_ARM64=ON -DSUPPORT_ARM32=OFF -DSUPPORT_X86=ON -DSUPPORT_RISCV=ON -DCMAKE_BUILD_TYPE=Release

cli_build:
	cmake -G Ninja -B build2 -DSUPPORT_ARM64=ON -DSUPPORT_ARM32=OFF -DSUPPORT_X86=ON -DSUPPORT_RISCV=ON -DUNICORN_SUPPORT=OFF

serve:
	python3 serve.py

define deploy
	mkdir -p deploy/$(1)
	cp -d -r www/* deploy/$(1)
	rm -rf deploy/$(1)/build && mkdir -p deploy/$(1)/build
	cp build_$(1)/ret.js deploy/$(1)/build/
	cp build_$(1)/ret.wasm deploy/$(1)/build/
	python3 pphtml.py www/index.html $(1) > deploy/$(1)/index.html
endef
define deploydefault
	cp -d -r www/* deploy/
	rm -rf deploy/build && mkdir -p deploy/build
	cp build_$(1)/ret.js deploy/build/
	cp build_$(1)/ret.wasm deploy/build/
	python3 pphtml.py www/index.html $(1) > deploy/index.html
endef

.PHONY: deploy
deploy:
	rm -rf deploy
	mkdir -p deploy

	$(call deploydefault,x86)
	$(call deploy,arm64)
	$(call deploy,arm32)
	$(call deploy,riscv)

	zip -r ret.zip deploy

build_arm64:
	cmake -G Ninja -B build_arm64 -DCMAKE_TOOLCHAIN_FILE=$(CMAKE) -DCMAKE_BUILD_TYPE=Release -DSUPPORT_ARM64=ON

build_arm32:
	cmake -G Ninja -B build_arm32 -DCMAKE_TOOLCHAIN_FILE=$(CMAKE) -DCMAKE_BUILD_TYPE=Release -DSUPPORT_ARM32=ON

build_x86:
	cmake -G Ninja -B build_x86 -DCMAKE_TOOLCHAIN_FILE=$(CMAKE) -DCMAKE_BUILD_TYPE=Release -DSUPPORT_X86=ON

build_riscv:
	cmake -G Ninja -B build_riscv -DCMAKE_TOOLCHAIN_FILE=$(CMAKE) -DCMAKE_BUILD_TYPE=Release -DSUPPORT_RISCV=ON -DUNICORN_SUPPORT=OFF

# emscripten is very slow. run config in parallel.
config_all: build_arm64 build_arm32 build_x86 build_riscv

build_all:
	cmake --build build_arm64
	cmake --build build_arm32
	cmake --build build_x86
	cmake --build build_riscv

clean:
	rm -rf build_arm32 build_arm64 build_x86 build build_em deploy

.PHONY: build_arm64 build_arm32 build_x86 build_riscv config_all build_all clean deploy
