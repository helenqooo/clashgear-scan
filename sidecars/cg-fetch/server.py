#!/usr/bin/env python3
"""ClashGear link fetcher: downloads one public URL for ClashGear Scan's link scans, through the backend's
SSH tunnel only. Runs here, on the sandbox box, so malware hosts never see the shop's address.
"Authorization: Token <secret>" on every call.
  POST /fetch  {"url", "method"?: GET|POST|HEAD, "headers"?: {}, "body_b64"?, "max_bytes"?, "follow"?: true,
                "timeout"?: seconds}
     -> 200, body = 4-byte big-endian length + meta JSON + response body
        meta = {status, url (final), redirects: [{url, status, ip}], ip, headers: {...}, size, truncated, tls_verified}
     -> 422 {"error": "..."} when the address is refused or the host cannot be reached
SSRF guard: http/https on ports 80/443 only, every hop's name is resolved here and must be a public IPv4 address
(not this box, its LANs or the shop); the connection goes to that exact address. The cgfetch user is also fenced
by iptables (cg-fetch-guard.sh), so a bug here still cannot reach local services."""
import base64, hmac, http.client, ipaddress, json, os, socket, ssl, struct, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urljoin, urlsplit

TOKEN = open("/etc/cg-fetch.token").read().strip()
CAP = 110 * 1024 * 1024
# Your own hosts (the sandbox LAN, the web server) that link scans must never reach, comma-separated CIDRs.
BLOCKED = [ipaddress.ip_network(n.strip()) for n in os.environ.get("CG_FETCH_BLOCKED", "").split(",") if n.strip()]
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
KEEP_HEADERS = {"content-type", "content-disposition", "content-length", "content-encoding", "last-modified", "server", "location"}
slots = threading.BoundedSemaphore(4)

VERIFIED = ssl.create_default_context()
LOOSE = ssl.create_default_context()
LOOSE.check_hostname = False
LOOSE.verify_mode = ssl.CERT_NONE


class Refused(Exception):
    pass


def public_ip(host, port):
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise Refused("dns_failed")
    ips = [i[4][0] for i in infos]
    if not ips:
        raise Refused("dns_failed")
    for a in ips:
        ip = ipaddress.ip_address(a)
        if not ip.is_global or ip.is_multicast or any(ip in n for n in BLOCKED):
            raise Refused("blocked_address")
    return ips[0]


def connect(host, ip, port, https, ctx):
    sock = socket.create_connection((ip, port), timeout=30)
    if https:
        try:
            sock = ctx.wrap_socket(sock, server_hostname=host)
        except Exception:
            sock.close()
            raise
    conn = (http.client.HTTPSConnection if https else http.client.HTTPConnection)(host, port, timeout=30)
    conn.sock = sock  # already connected to the pinned address
    return conn


def fetch(spec):
    url = str(spec.get("url") or "")
    method = str(spec.get("method") or "GET").upper()
    if method not in ("GET", "POST", "HEAD"):
        raise Refused("bad_method")
    extra = {k: str(v) for k, v in (spec.get("headers") or {}).items()
             if k.lower() not in ("host", "content-length", "connection", "transfer-encoding")}
    body = base64.b64decode(spec["body_b64"]) if spec.get("body_b64") else None
    cap = min(int(spec.get("max_bytes") or CAP), CAP)
    follow = spec.get("follow", True)
    deadline = time.monotonic() + min(float(spec.get("timeout") or 120), 180)
    redirects, cookies, verified = [], {}, True
    for _ in range(9):
        u = urlsplit(url)
        if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
            raise Refused("bad_url")
        https = u.scheme == "https"
        port = u.port or (443 if https else 80)
        if port not in (80, 443):
            raise Refused("bad_port")
        ip = public_ip(u.hostname, port)
        try:
            conn = connect(u.hostname, ip, port, https, VERIFIED)
        except ssl.SSLCertVerificationError:
            # malware hosts often have broken certificates; we only read the bytes, so go on and say so
            conn, verified = connect(u.hostname, ip, port, https, LOOSE), False
        h = {"User-Agent": UA, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "identity", **extra}
        if cookies and not any(k.lower() == "cookie" for k in extra):
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        conn.request(method, (u.path or "/") + (f"?{u.query}" if u.query else ""), body=body, headers=h)
        r = conn.getresponse()
        for c in r.headers.get_all("Set-Cookie") or []:
            kv = c.split(";", 1)[0]
            if "=" in kv:
                k, v = kv.split("=", 1)
                cookies[k.strip()] = v.strip()
        loc = r.getheader("Location")
        if follow and r.status in (301, 302, 303, 307, 308) and loc:
            redirects.append({"url": url, "status": r.status, "ip": ip})
            url = urljoin(url, loc)
            if r.status == 303 or (r.status in (301, 302) and method == "POST"):
                method, body = "GET", None
            conn.close()
            continue
        data, truncated = bytearray(), False
        while method != "HEAD":
            if time.monotonic() > deadline:
                conn.close()
                raise Refused("timeout")
            chunk = r.read(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > cap:
                truncated = True
                del data[cap:]
                break
        conn.close()
        headers = {k.lower(): v[:500] for k, v in r.getheaders() if k.lower() in KEEP_HEADERS}
        meta = {"status": r.status, "url": url, "redirects": redirects, "ip": ip, "headers": headers,
                "size": len(data), "truncated": truncated, "tls_verified": verified or not https}
        return meta, bytes(data)
    raise Refused("too_many_redirects")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, code, payload, ctype="application/json"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        if not hmac.compare_digest(auth.encode(), f"Token {TOKEN}".encode()):
            return self.reply(403, {"error": "forbidden"})
        if self.path != "/fetch":
            return self.reply(404, {"error": "not_found"})
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > 2_000_000:
            return self.reply(413, {"error": "too_large"})
        try:
            spec = json.loads(self.rfile.read(n))
        except ValueError:
            return self.reply(400, {"error": "bad_json"})
        if not slots.acquire(timeout=90):
            return self.reply(503, {"error": "busy"})
        t0 = time.monotonic()
        try:
            meta, data = fetch(spec)
        except Refused as e:
            return self.reply(422, {"error": str(e)})
        except (socket.timeout, TimeoutError):
            return self.reply(422, {"error": "timeout"})
        except ssl.SSLError:
            return self.reply(422, {"error": "tls_failed"})
        except (OSError, http.client.HTTPException) as e:
            return self.reply(422, {"error": "connect_failed", "detail": str(e)[:200]})
        finally:
            slots.release()
        host = urlsplit(meta["url"]).hostname
        print(f"fetch {host} {meta['status']} {meta['size']}B {time.monotonic() - t0:.1f}s", file=sys.stderr, flush=True)
        m = json.dumps(meta).encode()
        self.reply(200, struct.pack(">I", len(m)) + m + data, "application/octet-stream")

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8004), Handler).serve_forever()
