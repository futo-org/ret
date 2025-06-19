CMAKE ?= emscripten.cmake

CMAKE := /home/daniel/Pulled/emsdk/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake

debug_build:
	cmake -G Ninja -B build -DCMAKE_TOOLCHAIN_FILE=$(CMAKE) -DSUPPORT_ARM64=ON -DSUPPORT_ARM32=ON -DSUPPORT_X86=ON -DCMAKE_BUILD_TYPE=Release

cli_build:
	cmake -G Ninja -B build2 -DSUPPORT_ARM64=ON -DSUPPORT_ARM32=ON -DSUPPORT_X86=ON -DUNICORN_SUPPORT=OFF

serve:
	python3 -m http.server 8000

.PHONY: deploy
deploy:
	mkdir -p deploy
	rm -rf deploy/*

	mkdir -p deploy/arm64
	cp -r www/* deploy/arm64
	rm -rf deploy/arm64/build && mkdir deploy/arm64/build
	cp build_arm64/ret.js deploy/arm64/build/
	cp build_arm64/ret.wasm deploy/arm64/build/

	cp www/landing.html > deploy/index.html

build_arm64:
	cmake -G Ninja -B build_arm64 -DCMAKE_TOOLCHAIN_FILE=$(CMAKE) -DCMAKE_BUILD_TYPE=Release -DSUPPORT_ARM64=ON

build_arm32:
	cmake -G Ninja -B build_arm32 -DCMAKE_TOOLCHAIN_FILE=$(CMAKE) -DCMAKE_BUILD_TYPE=Release -DSUPPORT_ARM32=ON

build_x86:
	cmake -G Ninja -B build_x86 -DCMAKE_TOOLCHAIN_FILE=$(CMAKE) -DCMAKE_BUILD_TYPE=Release -DSUPPORT_X86=ON

# emscripten is very slow. run config in parallel.
config_all: build_arm64
# build_arm32 build_x86

build_all:
	cmake --build build_arm64
	#cmake --build build_arm32
	#cmake --build build_x86

clean:
	rm -rf build_arm32 build_arm64 build_x86 build build_em deploy
