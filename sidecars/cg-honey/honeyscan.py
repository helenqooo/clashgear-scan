"""ClashGear Token Tuzağı, host side: where did the run's bait values end up?

scan(task, markers) looks for every marker (raw, UTF-16, base64 at any alignment, hex) in
  - the guest's outbound TCP streams in dump.pcap (also inside zip archives and gzip streams in them),
  - the HTTP(S) request bodies CAPE decrypted with the guest's TLS keys (network/<sha256>),
  - the files CAPE's monitor captured (files/: stealers often delete their zip after sending it),
and lists the outbound connections (TLS server name / Host header, bytes sent), Discord webhooks and Telegram
bot tokens seen anywhere in them. The guest module's own report (aux/cghoney_report.json) comes back with it."""
import base64
import io
import json
import os
import re
import socket
import struct
import zipfile
import zlib

ROOT = "/opt/CAPEv2/storage/analyses"
GUEST = "192.168.1.101"
MAX_FLOW = 60 * 1024 * 1024
MAX_TOTAL = 300 * 1024 * 1024
WEBHOOK = re.compile(rb"https?://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api/(?:v\d+/)?webhooks/(\d{16,21})/([A-Za-z0-9_-]{50,80})")
BOT = re.compile(rb"bot(\d{8,11}:[A-Za-z0-9_-]{35})")
PRIVATE = re.compile(r"^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|2(2[4-9]|[3-5]\d)\.)")
CHAT_ID = re.compile(rb"chat_id[\"'=:\s]{1,4}(-?\d{5,16})")


def forms(marker):
    """Byte strings that reveal the marker however a stealer encoded it."""
    m = marker.encode()
    out = {"raw": [m], "utf16": [marker.encode("utf-16-le")], "hex": [m.hex().encode()], "base64": []}
    n = len(m)
    for k in range(3):
        enc = base64.b64encode(b"\0" * k + m)
        i0, i1 = -(-8 * k // 6), (8 * (k + n)) // 6
        inner = enc[i0:i1]
        if len(inner) >= 12:
            out["base64"].append(inner)
            out["base64"].append(inner.replace(b"+", b"-").replace(b"/", b"_"))
    return out


def find(data, table):
    hits = {}
    for mid, enc in table.items():
        for kind, variants in enc.items():
            if any(v in data for v in variants):
                hits.setdefault(mid, []).append(kind)
    return hits


def unpack_all(data, depth=0):
    """Yields (label, bytes) for the data itself and for zip members / gzip streams found inside it."""
    yield "", data
    if depth >= 2:
        return
    for off in [m.start() for m in re.finditer(rb"PK\x03\x04", data[:MAX_FLOW])][:20]:
        try:
            with zipfile.ZipFile(io.BytesIO(data[off:])) as z:
                for info in z.infolist()[:400]:
                    if info.file_size > 50 * 1024 * 1024:
                        continue
                    try:
                        inner = z.read(info)
                    except Exception:  # noqa: BLE001
                        continue
                    for label, blob in unpack_all(inner, depth + 1):
                        yield f"zip:{info.filename[:120]}{('/' + label) if label else ''}", blob
            break  # the first readable archive covers the later local headers
        except Exception:  # noqa: BLE001
            continue
    for off in [m.start() for m in re.finditer(rb"\x1f\x8b\x08", data[:MAX_FLOW])][:10]:
        try:
            d = zlib.decompressobj(47).decompress(data[off:], 80 * 1024 * 1024)
            for label, blob in unpack_all(d, depth + 1):
                yield f"gzip{('/' + label) if label else ''}", blob
        except Exception:  # noqa: BLE001
            continue


def sni_of(payload):
    try:
        if payload[0] != 0x16 or payload[5] != 0x01:
            return None
        p = 9 + 2 + 32
        p += 1 + payload[p]
        p += 2 + struct.unpack(">H", payload[p:p + 2])[0]
        p += 1 + payload[p]
        end = p + 2 + struct.unpack(">H", payload[p:p + 2])[0]
        p += 2
        while p + 4 <= end:
            typ, ln = struct.unpack(">HH", payload[p:p + 4])
            if typ == 0:
                n = struct.unpack(">H", payload[p + 7:p + 9])[0]
                return payload[p + 9:p + 9 + n].decode("ascii", "replace")
            p += 4 + ln
    except (IndexError, struct.error):
        return None
    return None


def flows_of(pcap):
    """Outbound TCP payload per connection from the guest, in sequence order."""
    flows = {}
    total = 0
    with open(pcap, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            return {}
        endian = "<" if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        link = struct.unpack(endian + "I", head[20:24])[0]
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            incl = struct.unpack(endian + "IIII", rec)[2]
            pkt = f.read(incl)
            off = 14 if link == 1 else 16 if link == 113 else 0
            if link == 1 and pkt[12:14] == b"\x81\x00":
                off = 18
            ip = pkt[off:]
            if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
                continue
            src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
            # only traffic to the internet (not the analyzer's own uploads to the host's result server)
            if src != GUEST or PRIVATE.match(dst):
                continue
            ihl = (ip[0] & 15) * 4
            tlen = struct.unpack(">H", ip[2:4])[0]
            tcp = ip[ihl:tlen]
            if len(tcp) < 20:
                continue
            sport, dport, seq = struct.unpack(">HHI", tcp[:8])
            data = tcp[(tcp[12] >> 4) * 4:]
            if not data:
                continue
            fl = flows.setdefault((dst, dport, sport), {"segs": {}, "size": 0})
            if seq in fl["segs"] or fl["size"] > MAX_FLOW or total > MAX_TOTAL:
                continue
            fl["segs"][seq] = data
            fl["size"] += len(data)
            total += len(data)
    out = {}
    for key, fl in flows.items():
        segs = sorted(fl["segs"].items())
        out[key] = b"".join(d for _, d in segs)
    return out


def scan(task, markers):
    base = os.path.join(ROOT, str(task))
    table = {m["id"]: forms(m["s"]) for m in markers if len(m.get("s", "")) >= 8}
    res = {"guest": None, "flows": [], "hits": [], "webhooks": [], "bots": [], "chat_ids": []}
    # The guest uploads a snapshot every 20 s and a final one at the end (which may not make it before the VM stops).
    aux = os.path.join(base, "aux")
    names = sorted(n for n in (os.listdir(aux) if os.path.isdir(aux) else []) if n.startswith("cghoney_report") and n.endswith(".json"))
    for name in (["cghoney_report_final.json"] if "cghoney_report_final.json" in names else []) + names[::-1]:
        try:
            with open(os.path.join(aux, name), "rb") as f:
                res["guest"] = json.load(f)
            res["guest"]["snapshot"] = name
            break
        except (OSError, ValueError):
            continue
    hooks, bots, chats = {}, set(), set()

    def extras(blob):
        for m in WEBHOOK.finditer(blob):
            hooks[m.group(1).decode()] = m.group(0).decode()
        for m in BOT.finditer(blob):
            bots.add(m.group(1).decode())
        if b"telegram" in blob or bots:
            for m in CHAT_ID.finditer(blob):
                chats.add(m.group(1).decode())

    def look(blob, where):
        found = {}
        archive = False
        for label, part in unpack_all(blob):
            h = find(part, table)
            if h and label:
                archive = True
            for mid, kinds in h.items():
                found.setdefault(mid, set()).update(kinds if not label else [k + "+" + label.split(":")[0].split("/")[0] for k in kinds])
            extras(part)
        if found:
            res["hits"].append({**where, "archive": archive, "markers": {k: sorted(v) for k, v in found.items()}})

    pcap = os.path.join(base, "dump.pcap")
    if os.path.isfile(pcap):
        for (dst, dport, sport), data in flows_of(pcap).items():
            host = sni_of(data)
            if not host and data[:8].split(b" ")[0] in (b"GET", b"POST", b"PUT", b"HEAD", b"PATCH"):
                m = re.search(rb"\r\nHost:\s*([^\r\n:]+)", data[:8192], re.I)
                host = m.group(1).decode("ascii", "replace") if m else None
            res["flows"].append({"dst": dst, "dport": dport, "host": host, "bytes": len(data), "tls": bool(data[:1] == b"\x16")})
            look(data, {"where": "tcp", "dst": dst, "dport": dport, "host": host})

    # Decrypted / plain HTTP bodies, mapped back to their request.
    reqs = {}
    try:
        with open(os.path.join(base, "reports", "report.json"), "rb") as f:
            raw = f.read()
        extras(raw)
        net = json.loads(raw).get("network", {})
        for h in (net.get("http_ex") or []) + (net.get("https_ex") or []):
            sha = (h.get("req") or {}).get("sha256")
            if sha:
                reqs[sha] = {"host": h.get("host"), "uri": h.get("uri"), "method": h.get("method"), "dst": h.get("dst"), "dport": h.get("dport"), "proto": h.get("protocol")}
    except (OSError, ValueError):
        pass
    netdir = os.path.join(base, "network")
    if os.path.isdir(netdir):
        for name in os.listdir(netdir):
            if name not in reqs:
                continue  # response bodies
            p = os.path.join(netdir, name)
            if os.path.getsize(p) <= MAX_FLOW:
                with open(p, "rb") as f:
                    look(f.read(), {"where": "https" if reqs[name].get("proto") == "https" else "http", **reqs[name]})

    files = os.path.join(base, "files")
    names = {}
    try:
        with open(os.path.join(base, "files.json"), "r") as f:
            for line in f:
                try:
                    j = json.loads(line)
                    names[os.path.basename(j.get("path", ""))] = (j.get("filepath") or "")
                except ValueError:
                    continue
    except OSError:
        pass
    if os.path.isdir(files):
        for d, _, fs in os.walk(files):
            for fn in fs[:500]:
                p = os.path.join(d, fn)
                if os.path.getsize(p) <= MAX_FLOW:
                    with open(p, "rb") as f:
                        look(f.read(), {"where": "dropped", "path": names.get(fn) or fn})

    res["flows"] = sorted(res["flows"], key=lambda x: -x["bytes"])[:80]
    res["webhooks"] = sorted(hooks.values())[:20]
    res["bots"] = sorted(bots)[:10]
    res["chat_ids"] = sorted(chats)[:10]
    return res
