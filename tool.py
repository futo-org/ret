import argparse
import os
import shutil
import subprocess

def niceName(arch):
    match arch:
        case "x86":
            return "x86"
        case "arm64":
            return "Arm64"
        case "arm32":
            return "Arm"
        case "riscv":
            return "RISC-V"

# Process HTML file so it can be placed in a subdirectory and reference
# files from above directory
def pphtml(src_html, arch, top_level):
    with open(src_html) as f:
        data = f.read()
    
    data = data.replace('RET_VERSION', 'v4.0')
    data = data.replace('{{TITLE}}', 'Ret - Online ' + niceName(arch) + ' Assembler and Disassembler')
    data = data.replace('{{DESCRIPTION}}', "Online assembler and disassembler supporting ARM64, x86, ARM, Thumb, and RISC-V. Runs entirely client-side in WebAssembly.")
    if not top_level:
        paths_to_prefix = [
            "./bitbash",
            "favicon.ico",
            "style.css",
            "portrait.css",
            "dark-theme.css",
            "light-theme.css",
            "assets/arrow_drop_down_24dp_E3E3E3_FILL0_wght400_GRAD0_opsz48.png",
            "assets/settings_64dp_E3E3E3_FILL0_wght400_GRAD0_opsz48.png",
            "assets/share_64dp_E3E3E3_FILL0_wght400_GRAD0_opsz48.png",
            "assets/ret.png",
            "lib/highlight.min.js",
            "lib/x86asm.js",
            "lib/armasm.js",
            "lib/codejar.js",
            "examples.js",
            "lib.js",
            "ui.js"
        ]
        for path in paths_to_prefix:
            data = data.replace(path, "../" + path)
        data = data.replace('"ret.js"', '"../ret.js"')
    return data

def ignore_build(dir, contents):
	return ['build'] if 'build' in contents else []

def deploy_target(arch, top_level):
    print("Compiling target " + arch)
    base_dst = ""
    if top_level:
        base_dst = "deploy"
        shutil.copytree("www", base_dst, ignore=ignore_build, symlinks=False, dirs_exist_ok=True)
    else:
        base_dst = f"deploy/{arch}"
        os.makedirs(base_dst, exist_ok=True)
        shutil.copyfile("www/index.html", os.path.join(base_dst, "index.html"))

    build_dir = os.path.join(base_dst, "build")
    if os.path.exists(build_dir):
        shutil.rmtree(build_dir)
    os.makedirs(build_dir, exist_ok=True)

    shutil.copyfile(f"build_{arch}/ret.js", os.path.join(build_dir, "ret.js"))
    shutil.copyfile(f"build_{arch}/ret.wasm", os.path.join(build_dir, "ret.wasm"))

    with open(os.path.join(base_dst, "index.html"), "w") as f:
        f.write(pphtml("www/index.html", arch, top_level))

def deploy():
    if os.path.exists("deploy"):
        shutil.rmtree("deploy")
    os.makedirs("deploy", exist_ok=True)

    deploy_target("x86", top_level=True)
    deploy_target("arm64", top_level=False)
    deploy_target("arm32", top_level=False)
    deploy_target("riscv", top_level=False)

    subprocess.run(["zip", "-r", "ret.zip", "deploy"], check=True)

def examples():
    out = open("www/examples.js", "w")
    def encode_js(data):
        return data.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '')
    def add(name, arch, file):
        d = open("examples/" + file, "r")
        out.write("addExample(\"" + name + "\", \"" + arch + "\", \"" + encode_js(d.read()) + "\");\n")

    # 'Hello World' file is required for each arch

    add("Hello World", "rv", "rv-hello.S")
    add("Registers", "rv", "rv-regs.S")

    add("Hello World", "arm32", "arm32-hello.S")
    add("Registers", "arm32", "arm32-regs.S")
    add("Jumps", "arm32", "arm32-jumps.S")
    add("Conditions", "arm32", "arm32-conditions.S")
    add("Functions", "arm32", "arm32-functions.S")
    add("Stack", "arm32", "arm32-stack.S")

    add("Hello World", "arm64", "arm64-hello.S")
    add("Registers", "arm64", "arm64-registers.S")
    add("Stack", "arm64", "arm64-stack.S")
    add("Functions", "arm64", "arm64-functions.S")
    add("Exception Levels", "arm64", "arm64-el.S")
    add("SIMD", "arm64", "arm64-simd.S")
    add("Mandelbrot", "arm64", "arm64-mandelbrot.S")
    #add("Hello World (PIC)", "arm64", "arm64-hello-pic.S")

#    add("Hello World", "x86gnu", "x86-hello.asm")
#    add("Hello World", "x86nasm", "x86-hello.asm")
    add("Hello World", "x86intel", "x86-hello.asm")
    add("Registers", "x86intel", "x86-regs.asm")
    add("Functions", "x86intel", "x86-functions.asm")
    add("Sierpinski", "x86intel", "x86-sierpinski.asm")

    out.close()
    print("updated www/examples.js")

def serve():
    from http.server import SimpleHTTPRequestHandler, HTTPServer
    from urllib.parse import urlparse

    class CORSHandler(SimpleHTTPRequestHandler):
        def end_headers(self):
            self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
            self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
            super().end_headers()

        def translate_path(self, path):
            root = os.path.abspath('www')
            path = urlparse(path).path

            if path == '/':
                return root

            for p in ('/arm64', '/arm32', '/x86', '/riscv'):
                if path == p or path.startswith(p + '/'):
                    return os.path.join(root, path.removeprefix(p).lstrip('/'))

            return os.path.join(root, path.lstrip('/'))

    print("http://localhost:8000/")
    HTTPServer(('localhost', 8000), CORSHandler).serve_forever()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--deploy', action='store_true')
    parser.add_argument('--examples', action='store_true')
    parser.add_argument('--serve', action='store_true')
    args = parser.parse_args()

    if args.deploy:
        deploy()
    if args.examples:
        examples()
    if args.serve:
        serve()

if __name__ == "__main__":
    main()
