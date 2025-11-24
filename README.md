# ret: Reverse-Engineering Tool

This is a quick and easy to use assembler/disassembler/emulator tool that runs in the browser through WebAssembly.
It's perfect for learning a new CPU architecture, quickly disassembling bytecode, or trying out ideas in assembly.

# Features
- Assemble, disassemble, and run X86, ARM64, ARM32, RISC-V, and PowerPC
- Smart hex parser and formatter - output as bytes, 32-bit integers, or C arrays
- Works entirely *client-side* in the browser through WebAssembly, no server required
- Incredibly lightweight - no unnecessary JS frameworks, assets, or cookies
- Customizable and ready for self-hosting - unpack a zip of static content into your web server

## Compiling WASM
Install emscripten (`sudo apt install emscripten`). It should be installed in `/usr/share/emscripten` on Debian/Ubuntu.  
If not, then you can install emsdk manually and use the [toolchain file](https://github.com/emscripten-core/emscripten/blob/main/cmake/Modules/Platform/Emscripten.cmake).
```
cmake -G Ninja -B build -DSUPPORT_ALL=ON -DCMAKE_TOOLCHAIN_FILE=/usr/share/emscripten/cmake/Modules/Platform/Emscripten.cmake
cmake --build build
```
Run it in a web server that mimicks the deployed version:
```
python3 tool.py --serve
```
## Compiling CLI
```
cmake -G Ninja -B buildcli -DSUPPORT_ALL=ON
cmake --build buildcli
```

# Credits

- Unicorn: https://github.com/unicorn-engine/unicorn/blob/master/COPYING
- Capstone: https://github.com/capstone-engine/capstone/blob/next/LICENSES/LICENSE.TXT
- Keystone: https://github.com/keystone-engine/keystone/blob/master/COPYING
- CodeJar: https://github.com/antonmedv/codejar/blob/master/LICENSE
- Highlight.js: https://github.com/highlightjs/highlight.js/blob/main/LICENSE
- Google Fonts icons: https://fonts.google.com/ (Apache License)
- Tinycpp: https://github.com/rofl0r/tinycpp
