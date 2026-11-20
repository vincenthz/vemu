"""Host HTTP server for scripts/e2e.sh.

usage: httpd.py DIR PORTFILE

Serves the files in DIR on 127.0.0.1 (GET) and answers POST /upload with
"md5=<hex> size=<n>" of the request body. Binds an ephemeral port and writes
it to PORTFILE once listening.
"""
import hashlib
import http.server
import os
import sys


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=sys.argv[1], **kw)

    def do_POST(self):
        left = int(self.headers.get("Content-Length", "0"))
        h, size = hashlib.md5(), 0
        while left > 0:
            chunk = self.rfile.read(min(left, 1 << 16))
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
            left -= len(chunk)
        body = f"md5={h.hexdigest()} size={size}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
tmp = sys.argv[2] + ".tmp"
with open(tmp, "w") as f:
    f.write(str(srv.server_address[1]))
os.rename(tmp, sys.argv[2])
srv.serve_forever()
