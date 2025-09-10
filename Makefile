CMAKE := /usr/share/emscripten/cmake/Modules/Platform/Emscripten.cmake

debug_build:
	cmake -G Ninja -B build -DCMAKE_TOOLCHAIN_FILE=$(CMAKE) -DSUPPORT_ALL=ON

cli_build:
	cmake -G Ninja -B buildcli -DSUPPORT_ALL=ON -DCMAKE_BUILD_TYPE=Debug

bug1:
	cmake --build buildcli && buildcli/ret --rv64 --asm examples/rv-func.S

pages-deploy:
	git tag -f 0.4.1-rc && git push -f origin 0.4.1-rc

serve:
	python3 tool.py --serve

deploy:
	python3 tool.py --deploy

examples:
	python3 tool.py --examples

build_arm64:
	cmake -G Ninja -B build_arm64 -DCMAKE_TOOLCHAIN_FILE=$(CMAKE) -DCMAKE_BUILD_TYPE=Release -DSUPPORT_ARM64=ON -DUSE_UNICORN_WASM=ON

build_arm32:
	cmake -G Ninja -B build_arm32 -DCMAKE_TOOLCHAIN_FILE=$(CMAKE) -DCMAKE_BUILD_TYPE=Release -DSUPPORT_ARM32=ON -DUSE_UNICORN_WASM=ON

build_x86:
	cmake -G Ninja -B build_x86 -DCMAKE_TOOLCHAIN_FILE=$(CMAKE) -DCMAKE_BUILD_TYPE=Release -DSUPPORT_X86=ON -DUSE_UNICORN_WASM=ON

build_riscv:
	cmake -G Ninja -B build_riscv -DCMAKE_TOOLCHAIN_FILE=$(CMAKE) -DCMAKE_BUILD_TYPE=Release -DSUPPORT_RISCV=ON

# emscripten is very slow. run config in parallel.
config_all: build_arm64 build_arm32 build_x86 build_riscv

build_all:
	cmake --build build_arm64
	cmake --build build_arm32
	cmake --build build_x86
	cmake --build build_riscv

clean:
	rm -rf build_arm32 build_arm64 build_x86 build build_em buildcli deploy *.zip __pycache__ build_riscv build2

.PHONY: build_arm64 build_arm32 build_x86 build_riscv config_all build_all clean deploy examples
