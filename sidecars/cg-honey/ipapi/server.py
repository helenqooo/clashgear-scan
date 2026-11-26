#!/usr/bin/env python3
"""cg-ipapi: answers the CAPE guests' plain-HTTP ip-api.com lookups (redirected here by cg-guard.sh) with a residential
Turkish connection. Stealers ask ip-api whether the IP is a data centre / proxy and quit when it is; the sandbox's real
egress is a hosting IP, so without this the Token Tuzağı baits are never touched. Only guests reach this (virbr1)."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

# The residential address the guests are told they have. Set CG_IPAPI_IP to a real residential IP of yours.
IP = os.environ.get("CG_IPAPI_IP", "203.0.113.57")
DATA = {
    "status": "success", "message": "", "continent": "Asia", "continentCode": "AS", "country": "Turkey", "countryCode": "TR",
    "region": "34", "regionName": "Istanbul", "city": "Istanbul", "district": "", "zip": "34000", "lat": 41.0136, "lon": 28.9550,
    "timezone": "Europe/Istanbul", "offset": 10800, "currency": "TRY", "isp": "Turk Telekom", "org": "TurkTelekom",
    "as": "AS9121 Turk Telekomunikasyon Anonim Sirketi", "asname": "TTNET", "reverse": f"{IP}.dynamic.ttnet.com.tr",
    "mobile": False, "proxy": False, "hosting": False, "query": IP,
}
DEFAULT = ["status", "country", "countryCode", "region", "regionName", "city", "zip", "lat", "lon", "timezone", "isp", "org", "as", "query"]

def fields_of(q):
    f = (q.get("fields") or [""])[0]
    if not f or f.isdigit():
        return DEFAULT
    return [x for x in f.split(",") if x in DATA] or DEFAULT

def line_val(v):
    return ("true" if v else "false") if isinstance(v, bool) else str(v)

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlsplit(self.path); q = parse_qs(u.query); fs = fields_of(q)
        kind = u.path.strip("/").split("/")[0] or "json"
        if kind == "line":
            body, ctype = ("\n".join(line_val(DATA[f]) for f in fs) + "\n"), "text/plain; charset=utf-8"
        elif kind == "csv":
            body, ctype = ",".join(line_val(DATA[f]) for f in fs) + "\n", "text/csv; charset=utf-8"
        else:
            body, ctype = json.dumps({f: DATA[f] for f in fs}), "application/json; charset=utf-8"
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b)))
        self.send_header("Access-Control-Allow-Origin", "*"); self.send_header("X-Ttl", "60"); self.send_header("X-Rl", "44")
        self.end_headers(); self.wfile.write(b)
    do_HEAD = do_GET
    def log_message(self, *a):
        pass

ThreadingHTTPServer(("192.168.1.1", 2043), H).serve_forever()
