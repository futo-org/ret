# ret: Reverse-Engineering Tool

A quick and easy reverse-engineering tool that runs in the browser through WebAssembly.
This tool makes it as easy as possible to disassemble bits of assembly or try out snippets of code. 

# Features
- Quickly assemble, disassemble, and run ARM64, ARM32, RISC, and X86
- Paste in a text hex sequence and cleanly format it regardless of formatting
- Works entirely in browser, no server required
- Ready for self-hosting - unpack a zip of static content into your web server 
- Optional fallback on godbolt API for better assembler error messages

# Roadmap
- [x] CLI tool
- [x] Capstone/Keystone compiling in wasm
- [x] Run Unicorn in wasm
- [x] Improved UI
- [x] Use godbolt as a optional assembler pass
- [ ] Merge in https://github.com/unicorn-engine/unicorn/pull/850/files (?) (looks like https://github.com/unicorn-engine/unicorn/tree/staging will work)
- [ ] Allow different x86 syntax
- [ ] Use godbolt or [xcc](https://github.com/tyfkda/xcc) as a C compiler
- [ ] Implement all improved hex transforms

# Compiling WASM
Install emscripten (`sudo apt install emscripten`). It should located in `/usr/share/emscripten` on Debian/Ubuntu.  
If not, then you can supply your own [toolchain file](https://github.com/emscripten-core/emscripten/blob/main/cmake/Modules/Platform/Emscripten.cmake) and it should work fine.
```
cmake -G Ninja -B build -DCMAKE_TOOLCHAIN_FILE=emscripten.cmake
cmake --build build
```
Run it in a web server:
```
python3 -m http.server 8000
```

# Credits

- Unicorn: https://github.com/unicorn-engine/unicorn/blob/master/COPYING
- Capstone: https://github.com/capstone-engine/capstone/blob/next/LICENSES/LICENSE.TXT
- Keystone: https://github.com/keystone-engine/keystone/blob/master/COPYING
- CodeJar: https://github.com/antonmedv/codejar/blob/master/LICENSE
- Highlight.js: https://github.com/highlightjs/highlight.js/blob/main/LICENSE
