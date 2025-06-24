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
		parsed_path = urlparse(path).path

		if parsed_path in ('/', '/index.html'):
			return os.path.join(root, 'landing.html')
		if parsed_path in ('/', '/favicon.ico'):
			return os.path.join(root, 'favicon.ico')
		if parsed_path.startswith(('/arm64', '/arm32', '/x86', '/riscv')):
			parts = parsed_path.strip('/').split('/', 1)
			subpath = parts[1] if len(parts) > 1 else ''
			return os.path.join(root, subpath)
		return os.path.join(root, parsed_path.lstrip('/'))

print("http://localhost:8000/")
HTTPServer(('localhost', 8000), CORSHandler).serve_forever()
