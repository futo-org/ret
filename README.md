# ret: Reverse-Engineering Tool

A quick and easy reverse-engineering tool that runs in the browser through WebAssembly.
This tool makes it as easy as possible to disassemble bits of assembly or try out snippets of code. 

- [x] CLI tool
- [x] Capstone/Keystone compiling in wasm
- [ ] Improved UI (Dear ImGui? Some other web framework?)
- [ ] Option to use godbolt as assembler
- [ ] Compile UnicornVM as wasm
- [ ] Use godbolt as C compiler

The legacy version made using unicorn.js, capstone.js, and keystone.js is available here:
- https://s1.danielc.dev/re
- https://s1.danielc.dev/re64
- https://s1.danielc.dev/re86
