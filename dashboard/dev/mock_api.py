"""Stdlib mock of the lab API + static server: python dev/mock_api.py [port]"""
import json, os, random, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODS = [dict(slug=s, title=s.replace("_", " ").title(), description=f"Mock description for {s}.", category=c, enabled=True)
        for s, c in [("tls_fingerprint", "passive"), ("h2_fingerprint", "passive"), ("header_order", "passive"), ("abck_cookie", "cookie"),
                     ("sensor_data", "js"), ("proof_of_work", "js"), ("behavioral", "behavioral"), ("ip_reputation", "network")]]
REPORTS, SUBS = [], []

def fake():
    m = random.choice(MODS)["slug"]; lab = random.choice(["", "naive", "curl_cffi", "playwright"])
    bad = lab == "naive" or (lab == "curl_cffi" and m in ("abck_cookie", "sensor_data", "behavioral"))
    sc = random.randint(60, 95) if bad else random.randint(0, 20)
    return dict(id=uuid.uuid4().hex[:12], ts=time.time(), method="GET", path="/protected/" + m, client_ip="172.18.0.1",
        user_agent="Mozilla/5.0 Chrome/126" if lab != "naive" else "python-requests/2.32", score=sc, blocked=bad, client_label=lab,
        signals=[dict(module=m, verdict="fail" if bad else "pass", score=sc, reason="Mock: JA3 unknown to browser set" if bad else "Mock: matches Chrome", details={"ja3": "771,4865-4866"})],
        fingerprint=dict(ja3="771,4865-4866,0-23", ja3_hash="abc123", ja4="t13d1516h2_x_y", h2="1:65536;4:6291456;6:262144|15663105|0|m,a,s,p", header_order="Host,User-Agent,Accept"),
        headers=[["host", "localhost"], ["user-agent", "x"], ["accept", "*/*"]], cookies={"bm_sz": "abc~1"})

def emit():
    while True:
        time.sleep(2); r = fake(); REPORTS.append(r)
        for q in list(SUBS): q.append(r)

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send_json(self, o, code=200):
        b = json.dumps(o).encode(); self.send_response(code); self.send_header("content-type", "application/json"); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        p = self.path
        if p.startswith("/api/modules"): return self.send_json(MODS)
        if p.startswith("/api/requests"): return self.send_json(REPORTS[-100:][::-1])
        if p.startswith("/api/feed"):
            self.send_response(200); self.send_header("content-type", "text/event-stream"); self.end_headers(); q = []; SUBS.append(q)
            try:
                while True:
                    while q: self.wfile.write(f"event: report\ndata: {json.dumps(q.pop(0))}\n\n".encode()); self.wfile.flush()
                    self.wfile.write(b": ka\n\n"); self.wfile.flush(); time.sleep(0.5)
            except OSError: SUBS.remove(q); return
        f = os.path.join(ROOT, "index.html" if p == "/" else p.lstrip("/").split("?")[0])
        if not os.path.isfile(f): self.send_response(404); self.end_headers(); return
        b = open(f, "rb").read(); self.send_response(200)
        self.send_header("content-type", {"js": "text/javascript", "css": "text/css"}.get(f.rsplit(".", 1)[-1], "text/html")); self.end_headers(); self.wfile.write(b)
    def do_PUT(self):
        n = int(self.headers.get("content-length", 0)); body = json.loads(self.rfile.read(n) or b"{}")
        for m in MODS:
            if self.path.endswith(m["slug"]): m["enabled"] = body.get("enabled", True)
        self.send_json({"ok": True})
    def do_POST(self): REPORTS.clear(); self.send_json({"ok": True})

if __name__ == "__main__":
    import sys
    for _ in range(12): REPORTS.append(fake())
    threading.Thread(target=emit, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 3100), H).serve_forever()
