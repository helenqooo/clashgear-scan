#!/usr/bin/env python3
"""Hands files CAPE captured during an analysis to the ClashGear backend (through its SSH tunnel only).
GET /<kind>/<task>/<sha256> with "Authorization: Token <secret>"; kind = dropped | payload | procdump.
POST /honey/<task>: Token Tuzağı results (honeyscan.py)."""
import hmac, json, os, re
import honeyscan
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = "/opt/CAPEv2/storage/analyses"
DIRS = {"dropped": "files", "payload": "CAPE", "procdump": "procdump"}
TOKEN = open("/etc/cg-files.token").read().strip()
PATH = re.compile(r"^/(dropped|payload|procdump)/(\d{1,9})/([0-9a-f]{64})$")
READY = re.compile(r"^/ready/(\d{1,9})/([0-9a-f]{2,400})$")
# Files a package uploaded (e.g. cg_vmpunpack's unpacked images and tool logs): list, or one by name.
PKG = re.compile(r"^/package/(\d{1,9})(?:/([A-Za-z0-9_.-]{1,120}))?$")
MAX = 64 * 1024 * 1024

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if not hmac.compare_digest(auth, f"Token {TOKEN}"):
            return self.send_error(401)
        r = READY.match(self.path)
        if r:
            return self.ready(r.group(1), bytes.fromhex(r.group(2)).decode("utf-8", "replace"))
        k = PKG.match(self.path)
        if k:
            return self.package(k.group(1), k.group(2))
        m = PATH.match(self.path)
        if not m:
            return self.send_error(404)
        kind, task, sha = m.groups()
        base = os.path.realpath(os.path.join(ROOT, task, DIRS[kind]))
        hit = None
        for d, _, files in os.walk(base):
            for f in files:
                if f == sha or f.startswith(sha):
                    hit = os.path.join(d, f)
                    break
            if hit:
                break
        if not hit or not os.path.realpath(hit).startswith(base + os.sep) or os.path.getsize(hit) > MAX:
            return self.send_error(404)
        data = open(hit, "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_POST(self):
        # Token Tuzağı: POST /honey/<task> {"markers": [{"id", "s"}]} -> where the run's bait values went.
        if not hmac.compare_digest(self.headers.get("Authorization", ""), f"Token {TOKEN}"):
            return self.send_error(401)
        m = re.match(r"^/honey/(\d{1,9})$", self.path)
        if not m:
            return self.send_error(404)
        try:
            n = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(min(n, 1024 * 1024)) or b"{}")
            res = honeyscan.scan(int(m.group(1)), [x for x in req.get("markers", []) if isinstance(x, dict)][:80])
        except Exception as e:  # noqa: BLE001
            res = {"error": str(e)[:300]}
        body = json.dumps(res).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def package(self, task, name):
        # cg_vmpunpack uploads into aux/ as cgvmp_<name> (package_files is not on CAPE's upload whitelist).
        base = os.path.realpath(os.path.join(ROOT, task, "aux"))
        if not name:
            files = []
            if os.path.isdir(base):
                for f in sorted(os.listdir(base)):
                    p = os.path.join(base, f)
                    if f.startswith("cgvmp_") and os.path.isfile(p):
                        files.append({"name": f[len("cgvmp_"):], "size": os.path.getsize(p)})
            body = json.dumps({"files": files}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        p = os.path.realpath(os.path.join(base, "cgvmp_" + name))
        if not p.startswith(base + os.sep) or not os.path.isfile(p) or os.path.getsize(p) > MAX:
            return self.send_error(404)
        data = open(p, "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def ready(self, task, name):
        """True once the monitored desktop shell has seen the sample sitting on the desktop."""
        needle = ("Desktop\\" + os.path.basename(name)).lower()
        hits = (needle.encode("utf-16-le"), needle.encode("utf-8"))
        found = False
        logs = os.path.join(ROOT, task, "logs")
        if os.path.isdir(logs):
            for f in os.listdir(logs):
                try:
                    data = open(os.path.join(logs, f), "rb").read().lower()
                except OSError:
                    continue
                if any(h in data for h in hits):
                    found = True
                    break
        body = (b'{"ready": true}' if found else b'{"ready": false}')
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

ThreadingHTTPServer(("127.0.0.1", 8001), H).serve_forever()
