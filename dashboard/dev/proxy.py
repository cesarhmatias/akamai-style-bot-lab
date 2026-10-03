"""Dev proxy: serve the dashboard statics and forward /api/* and /healthz to a real API.

    # terminal 1 (memory store, no Redis):
    cd api && ../.venv/bin/uvicorn app.main:create_app --factory --port 8099
    # terminal 2:
    python dashboard/dev/proxy.py [listen_port=3100] [upstream=127.0.0.1:8099]

Stdlib only. SSE (/api/feed) is streamed through chunk by chunk. Not part of the Docker image.
"""
import http.client
import mimetypes
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPSTREAM = (sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1:8099").split(":")
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authorization", "proxy-authenticate"}
mimetypes.add_type("text/javascript", ".js")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _forward(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else None
        conn = http.client.HTTPConnection(UPSTREAM[0], int(UPSTREAM[1]), timeout=3600)
        try:
            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP | {"host"}}
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
        except OSError:
            msg = b'{"detail":"upstream unreachable"}'
            self.send_response(502)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return
        stream = "text/event-stream" in (resp.getheader("content-type") or "")
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in HOP | {"content-length"}:
                self.send_header(k, v)
        self.send_header("connection", "close")
        self.end_headers()
        try:
            while chunk := (resp.read1(4096) if stream else resp.read(65536)):
                self.wfile.write(chunk)
                self.wfile.flush()
        except OSError:
            pass
        finally:
            conn.close()
            self.close_connection = True

    def _static(self):
        path = self.path.split("?")[0]
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        full = os.path.realpath(os.path.join(ROOT, rel))
        if not full.startswith(ROOT + os.sep) or "/dev/" in full or not os.path.isfile(full):
            self.send_response(404)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        data = open(full, "rb").read()
        self.send_response(200)
        self.send_header("content-type", mimetypes.guess_type(full)[0] or "application/octet-stream")
        self.send_header("content-length", str(len(data)))
        self.send_header("cache-control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _route(self):
        if self.path.startswith("/api/") or self.path == "/healthz":
            return self._forward()
        if self.command == "GET":
            return self._static()
        self.send_response(405)
        self.send_header("content-length", "0")
        self.end_headers()

    do_GET = do_POST = do_PUT = do_DELETE = _route


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3100
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
