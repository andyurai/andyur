from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        Path("/evidence/dispatched").write_text("yes")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"upstream executed")

    def log_message(self, *_):
        pass


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
