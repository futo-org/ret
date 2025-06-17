# ret: Reverse-Engineering Tool

A quick and easy reverse-engineering tool that runs in the browser through WebAssembly.
This tool makes it as easy as possible to disassemble bits of assembly or try out snippets of code. 

- [x] CLI tool
- [x] Capstone/Keystone compiling in wasm
- [x] Run Unicorn in wasm
- [x] Improved UI
- [x] Use godbolt as a optional assembler pass
- [ ] Allow different x86 syntax
- [ ] Use godbolt or [xcc](https://github.com/tyfkda/xcc) as a C compiler
- [ ] Implement all improved hex transforms

# Compiling WASM
Install emscripten (`sudo apt install emscripten`). It should located in `/usr/share/emscripten`.
```
cmake -G Ninja -B build_em -DCMAKE_TOOLCHAIN_FILE=emscripten.cmake
cmake --build build_em
```
Run it in a web server:
```
python3 -m http.server 8000
```

# Legacy version

The legacy version made using unicorn.js, capstone.js, and keystone.js will always be available here:

- https://s1.danielc.dev/re
- https://s1.danielc.dev/re64
- https://s1.danielc.dev/re86

(These are aliases to legacy/ in this repo)

# Credits

- Unicorn: https://github.com/unicorn-engine/unicorn/blob/master/COPYING
- Capstone: https://github.com/capstone-engine/capstone/blob/next/LICENSES/LICENSE.TXT
- Keystone: https://github.com/keystone-engine/keystone/blob/master/COPYING
