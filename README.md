# ret: Reverse-Engineering Tool

This is a quick and easy to use assembler/disassembler/emulator that runs in the browser through WebAssembly.
This tool makes it as easy as possible to disassemble bits of assembly or try out snippets of code.

# Features
- Quickly assemble, disassemble, and run ARM64, ARM32, RISC, and X86
- Smart hex parser and formatter - output as bytes, 32bit integers, or C arrays
- Works entirely in the browser through WebAssembly, no server required
- Incredibly lightweight - no unnecessary JS frameworks, assets, or cookies
- Ready for self-hosting - unpack a zip of static content into your web server

# Compiling WASM
Install emscripten (`sudo apt install emscripten`). It should be installed in `/usr/share/emscripten` on Debian/Ubuntu.  
If not, then you can install emsdk manually and use the [toolchain file](https://github.com/emscripten-core/emscripten/blob/main/cmake/Modules/Platform/Emscripten.cmake).
```
cmake -G Ninja -B build -DSUPPORT_ARM64=ON -DCMAKE_TOOLCHAIN_FILE=/usr/share/emscripten/cmake/Modules/Platform/Emscripten.cmake
cmake --build build
```
Run it in a web server that mimicks the deployed version:
```
python3 serve.py
```

The release version bundles 4 different ret binaries compiled for different architectures. This is done mainly to reduce page load times
(14mb to bundle all architectures, 1-2mb for one).

# Credits

- Unicorn: https://github.com/unicorn-engine/unicorn/blob/master/COPYING
- Capstone: https://github.com/capstone-engine/capstone/blob/next/LICENSES/LICENSE.TXT
- Keystone: https://github.com/keystone-engine/keystone/blob/master/COPYING
- CodeJar: https://github.com/antonmedv/codejar/blob/master/LICENSE
- Highlight.js: https://github.com/highlightjs/highlight.js/blob/main/LICENSE
- Google Fonts icons: https://fonts.google.com/ (Apache License)
