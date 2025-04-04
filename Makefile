all:
	cmake -G Ninja -B build -DCMAKE_TOOLCHAIN_FILE=/home/daniel/dotfiles/emscripten.cmake

serve:
	python3 -m http.server 8000
