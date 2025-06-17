debug_build:
	cmake -G Ninja -B build -DCMAKE_TOOLCHAIN_FILE=emscripten.cmake -DSUPPORT_ARM64=ON -DSUPPORT_ARM32=ON -DSUPPORT_X86=ON

serve:
	python3 -m http.server 8000

build_arm64:
	cmake -G Ninja -B build_arm64 -DCMAKE_TOOLCHAIN_FILE=emscripten.cmake -DCMAKE_BUILD_TYPE=Release -DSUPPORT_ARM64=ON

build_arm32:
	cmake -G Ninja -B build_arm32 -DCMAKE_TOOLCHAIN_FILE=emscripten.cmake -DCMAKE_BUILD_TYPE=Release -DSUPPORT_ARM32=ON

build_x86:
	cmake -G Ninja -B build_x86 -DCMAKE_TOOLCHAIN_FILE=emscripten.cmake -DCMAKE_BUILD_TYPE=Release -DSUPPORT_X86=ON

# emscripten is very slow. run config in parallel.
config_all: build_arm64 build_arm32 build_x86

build_all:
	cmake --build build_arm64
	cmake --build build_arm32
	cmake --build build_x86

clean:
	rm -rf build_arm32 build_arm64 build_x86 build build_em
