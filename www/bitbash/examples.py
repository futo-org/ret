import os

def encode_js(data):
	return data.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '')

with open("examples.js", "w") as out:
    out.write("let examples = [\n")
    for f in os.listdir("regs"):
        with open(os.path.join("regs", f), "r") as d:
            out.write("\"" + encode_js(d.read()) + "\",\n")
    out.write("];\n")

print("updated examples.js")
