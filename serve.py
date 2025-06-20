from http.server import SimpleHTTPRequestHandler, HTTPServer
import os

class CORSHandler(SimpleHTTPRequestHandler):
	def end_headers(self):
		self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
		self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
		super().end_headers()

	def translate_path(self, path):
		root = os.path.abspath('www')
		if path in ('/', '/index.html'):
			return os.path.join(root, 'landing.html')
		if path.startswith(('/arm64', '/arm32', '/x86', '/riscv64', 'riscv32')):
			path = path.split('/', 2)[-1] if '/' in path[1:] else ''
			return os.path.join(root, path)
		return os.path.join(root, path.lstrip('/'))

print("http://localhost:8000/")
HTTPServer(('localhost', 8000), CORSHandler).serve_forever()
