# -DCMAKE_BUILD_TYPE=Release

all:
	cmake -G Ninja -B build_em -DCMAKE_TOOLCHAIN_FILE=/home/daniel/dotfiles/emscripten.cmake

cli:
	cmake -G Ninja -B build

serve:
	python3 -m http.server 8000
