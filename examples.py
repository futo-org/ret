out = open("www/examples.js", "w")
def encode_js(data):
	return data.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '')
def add(name, arch, file):
    d = open("examples/" + file, "r")
    out.write("addExample(\"" + name + "\", \"" + arch + "\", \"" + encode_js(d.read()) + "\");\n")

# 'Hello World' file is required for each arch

add("Hello World", "rv", "rv-hello.S")
add("Registers", "rv", "rv-regs.S")

add("Registers", "arm32", "arm32-regs.S")
add("Jumps", "arm32", "arm32-jumps.S")
add("Conditions", "arm32", "arm32-conditions.S")
add("Functions", "arm32", "arm32-functions.S")
add("Stack", "arm32", "arm32-stack.S")
add("Hello World", "arm32", "arm32-hello.S")

add("Hello World", "arm64", "arm64-hello.S")
add("Registers", "arm64", "arm64-registers.S")
add("Exception Levels", "arm64", "arm64-el.S")
add("Exception Levels", "arm64", "arm64-simd.S")
#add("Hello World (PIC)", "arm64", "arm64-hello-pic.S")

add("Hello World", "x86gnu", "x86-hello-gnu.asm")
add("Hello World", "x86nasm", "x86_hello.asm")
add("Hello World", "x86intel", "x86-hello-gnu.asm")

out.close()
