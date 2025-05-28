# ret: Reverse-Engineering Tool

A quick and easy reverse-engineering tool that runs in the browser through WebAssembly.
This tool makes it as easy as possible to disassemble bits of assembly or try out snippets of code. 

- [x] CLI tool
- [x] Capstone/Keystone compiling in wasm
- [ ] Improved UI (Dear ImGui? Some other web framework?)
- [ ] Option to use godbolt as assembler
- [ ] Compile UnicornVM as wasm
- [ ] Use godbolt as C compiler

# Compiling WASM
NOTE: Wasm port is UNFINISHED. It doesn't do anything yet.

- You need the emscripten toolchain/SDK
- You also need a emscripten cmake toolchain file. You can use something similar to [mine](https://github.com/petabyt/dotfiles/blob/master/emscripten.cmake)
with a modified `EMSCRIPTEN_ROOT_PATH`
```
cmake -G Ninja -B build_em -DCMAKE_TOOLCHAIN_FILE=emscripten.cmake
cmake --build build_em
```
If you want to run it, you have to start a http server.
```
python3 -m http.server 8000
```

# Legacy version

The legacy version made using unicorn.js, capstone.js, and keystone.js will always be available here:

- https://s1.danielc.dev/re
- https://s1.danielc.dev/re64
- https://s1.danielc.dev/re86

(These are aliases to legacy/ in this repo)
