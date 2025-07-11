from http.server import SimpleHTTPRequestHandler, HTTPServer
import os
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
