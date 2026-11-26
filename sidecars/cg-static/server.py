#!/usr/bin/env python3
"""ClashGear static engines for Scan: YARA-Forge, capa (ATT&CK), FLOSS, Detect It Easy, ssdeep/TLSH, a stealer
config extractor (PyInstaller / Nuitka / zlib / zstd streams, .NET and FLOSS strings), Office macros (olevba) and
Android packages (androguard + jadx for Rune). Samples are parsed, never run. Reached only through the backend's
SSH tunnel; "Authorization: Token <secret>" on every call.
  POST /analyze/<sha256>     body = sample, X-Name: base64 file name  -> {"status": "running" | "done"}
  GET  /result/<sha256>                                               -> result JSON | {"status": "running"|"error"}
  POST /similar              {"tlsh", "ssdeep", "items": [[id, tlsh, ssdeep], ...]} -> {"hits": [[id, tlsh_dist, ssdeep_score]]}
  GET  /apk/<sha256>/search?q=<regex>      -> {"hits": [{"file", "line", "text"}]}   (jadx output, Rune only)
  GET  /apk/<sha256>/source?path=<file>    -> {"path", "text"}
Results and jadx output are swept after 2 h."""
import base64, hashlib, hmac, io, json, marshal, os, re, shutil, struct, subprocess, sys, threading, time, zipfile, zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import ppdeep, tlsh, yara

ROOT = "/opt/cg-static"
WORK = "/var/lib/cg-static"
BIN = ROOT + "/venv/bin"
TOKEN = open("/etc/cg-static.token").read().strip()
RULES = yara.load(ROOT + "/rules/yara-forge.yarc")
slots = threading.BoundedSemaphore(2)
state = {}  # sha -> {"status", "t", "result"?}
lock = threading.Lock()
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def run(cmd, timeout, cwd=None):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=cwd, env={**os.environ, "HOME": WORK, "PYTHONWARNINGS": "ignore"})
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -9, b"", b"timeout"


def kind_of(buf, name):
    if buf[:2] == b"MZ":
        return "pe"
    if buf[:4] == b"\x7fELF":
        return "elf"
    if buf[:4] == b"dex\n":
        return "dex"
    if buf[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if buf[:4] == b"PK\x03\x04":
        try:
            names = zipfile.ZipFile(io.BytesIO(buf)).namelist()
        except Exception:
            return "zip"
        if "AndroidManifest.xml" in names and any(n.endswith(".dex") for n in names):
            return "apk"
        if any(n.startswith(("word/", "xl/", "ppt/")) for n in names):
            return "ooxml"
        return "zip"
    if buf[:5] == b"%PDF-":
        return "pdf"
    return "other"


# ---------------------------------------------------------------------------------------------- engines
def do_yara(buf):
    out = []
    try:
        for m in RULES.match(data=buf, timeout=60):
            meta = {k: v for k, v in m.meta.items() if k in ("description", "author", "score", "quality", "date", "reference", "malware_family", "family")}
            out.append({"rule": m.rule, "tags": list(m.tags), "meta": meta})
    except yara.TimeoutError:
        out.append({"rule": "_timeout", "tags": [], "meta": {}})
    out.sort(key=lambda r: -int(r["meta"].get("score") or 0))
    return out[:60]


def do_die(path):
    code, out, _ = run(["diec", "-j", "-d", path], 60)
    try:
        doc = json.loads(out.decode("utf-8", "replace"))
    except Exception:
        return []
    found = []
    for d in doc.get("detects", []):
        for v in d.get("values", []):
            found.append({"type": v.get("type", ""), "name": v.get("name", ""), "version": v.get("version", ""), "string": v.get("string", "")})
    return found[:30]


def do_sign(path):
    """Authenticode check offline (no CRL fetch: the service has no network). verified: Signed | Invalid | Unsigned."""
    code, out, err = run(["osslsigncode", "verify", "-in", path, "-CAfile", "/etc/ssl/certs/ca-certificates.crt",
                          "-TSA-CAfile", "/etc/ssl/certs/ca-certificates.crt", "-ignore-cdp"], 40)
    t = (out + err).decode("utf-8", "replace")
    if "No signature found" in t or "Unable to extract signature" in t or not t.strip():
        return {"verified": "Unsigned"}
    m = re.search(r"Signer #0:\s*\n\s*Subject:\s*(.+)", t)
    if not m and "Signing certificate chain" not in t:
        return {"verified": "Unsigned"}
    subj = m.group(1).strip() if m else ""
    cn = re.search(r"/CN=([^/]+)", subj)
    org = re.search(r"/O=([^/]+)", subj)
    # Offline the CRL step always "fails"; what matters is an intact digest and a chain up to a trusted root.
    nver = re.search(r"Number of verified signatures:\s*(\d+)", t)
    ok = "MISMATCH" not in t and "Signing certificate chain verified" in t and ((code == 0 and "Signature verification: ok" in t) or (nver and int(nver.group(1)) > 0))
    return {"verified": "Signed" if ok else "Invalid", "signers": (cn.group(1) if cn else subj)[:120], "product": (org.group(1) if org else "")[:120]}


def do_capa(path):
    code, out, err = run([BIN + "/capa", "-j", "-q", "-r", ROOT + "/rules/capa-rules", "-s", ROOT + "/rules/capa-sigs", path], 480)
    if code == -9:
        return {"status": "timeout"}
    try:
        doc = json.loads(out.decode("utf-8", "replace"))
    except Exception:
        e = err.decode("utf-8", "replace")
        lim = "packed" if "packed" in e.lower() else "installer" if "installer" in e.lower() else "unsupported"
        return {"status": "limited", "reason": lim}
    caps, attack = [], {}
    for name, r in (doc.get("rules") or {}).items():
        meta = r.get("meta", {})
        if meta.get("lib") or str(meta.get("namespace", "")).startswith("internal"):
            continue
        att = []
        for a in meta.get("attack") or []:
            tid = a.get("id", "")
            att.append(tid)
            t = attack.setdefault(a.get("tactic", "?"), {})
            t[tid] = a.get("technique", "") + (f" / {a['subtechnique']}" if a.get("subtechnique") else "")
        mbc = [m.get("objective", "") + "::" + m.get("behavior", "") for m in meta.get("mbc") or []]
        caps.append({"name": name, "namespace": meta.get("namespace", ""), "attack": att, "mbc": mbc[:3]})
    caps.sort(key=lambda c: c["namespace"])
    return {"status": "done", "capabilities": caps[:200], "attack": {k: [{"id": i, "name": n} for i, n in sorted(v.items())] for k, v in attack.items()}}


def do_floss(path):
    code, out, _ = run([BIN + "/floss", "-j", "-q", "--only", "decoded", "stack", "tight", "--", path], 360)
    if code == -9:
        return {"status": "timeout"}
    try:
        doc = json.loads(out.decode("utf-8", "replace"))
    except Exception:
        return {"status": "limited"}
    s = doc.get("strings", {})
    pick = lambda k: list(dict.fromkeys(x.get("string", "") for x in s.get(k, []) if len(x.get("string", "")) >= 5))[:300]
    return {"status": "done", "decoded": pick("decoded_strings"), "stack": pick("stack_strings"), "tight": pick("tight_strings")}


# ------------------------------------------------------------------------------- embedded payloads
MEI = b"MEI\x0c\x0b\x0a\x0b\x0e"


def pyinstaller(buf):
    """Parses the PyInstaller CArchive (and its PYZ) without running anything; returns (info, blobs)."""
    pos = buf.rfind(MEI)
    if pos < 0:
        return None, []
    blobs, scripts, modules, encrypted = [], [], [], False
    try:
        if len(buf) >= pos + 88 and b"python" in buf[pos + 24:pos + 88].lower():
            pkg_len, toc_off, toc_len, pyver, libname = struct.unpack("!IIii64s", buf[pos + 8:pos + 88])
            end = pos + 88
        else:
            pkg_len, toc_off, toc_len, pyver = struct.unpack("!IIii", buf[pos + 8:pos + 24])
            libname, end = b"", pos + 24
        base = end - pkg_len
        p, toc_end = base + toc_off, base + toc_off + toc_len
        while p < toc_end:
            size, epos, csize, usize, flag, typ = struct.unpack("!IIIIBc", buf[p:p + 18])
            name = buf[p + 18:p + size].rstrip(b"\0").decode("utf-8", "replace")
            p += size
            data = buf[base + epos:base + epos + csize]
            if flag == 1:
                try:
                    data = zlib.decompress(data)
                except Exception:
                    continue
            t = typ.decode()
            if t == "s":
                scripts.append(name)
                blobs.append(("pyinstaller:" + name, data))
            elif t in ("z", "Z") and data[:4] == b"PYZ\0":
                (zoff,) = struct.unpack("!i", data[8:12])
                try:
                    toc = marshal.loads(data[zoff:])
                except Exception:
                    toc = []
                for item in toc if isinstance(toc, (list, tuple)) else toc.items():
                    mname, ent = item[0], item[1]
                    modules.append(str(mname))
                    try:
                        mpos, mlen = ent[1], ent[2]
                        blobs.append(("pyz:" + str(mname), zlib.decompress(data[mpos:mpos + mlen])))
                    except Exception:
                        encrypted = True
            elif t in ("m", "M", "x") and len(data) < 5_000_000:
                blobs.append(("pyinstaller:" + name, data))
        ver = f"{pyver // 100}.{pyver % 100}" if pyver >= 100 else f"{pyver // 10}.{pyver % 10}"
        return {"python": ver, "scripts": scripts[:20], "modules": len(modules), "notable_modules": notable(modules), "encrypted_pyz": encrypted, "lib": libname.strip(b"\0").decode("latin-1")}, blobs
    except Exception as e:
        return {"error": str(e)[:120], "scripts": scripts, "modules": len(modules), "notable_modules": notable(modules)}, blobs


NOTABLE = re.compile(r"^(browser_cookie3|discord_webhook|dhooks|discord|telebot|telegram|aiogram|pyautogui|pynput|keyboard|win32crypt|Crypto(dome)?\.Cipher|cryptography|sqlite3|requests|aiohttp|websocket|pyperclip|PIL\.ImageGrab|cv2|psutil|wmi|GPUtil|pytransform|pyarmor_runtime|winreg|ctypes|subprocess|socket|base64|zlib|marshal|lzma|pyaes|robloxpy|rookiepy|browser_history)\b")


def notable(mods):
    return sorted({m.split(".")[0] if not m.startswith("Crypto") else m for m in mods if NOTABLE.match(m)})[:40]


def compressed_streams(buf, budget=150_000_000):
    """zstd (Nuitka onefile) and zlib/gzip streams anywhere in the file; returns [(where, bytes)]."""
    out, used = [], 0
    try:
        import zstandard
        dctx = zstandard.ZstdDecompressor()
        i = buf.find(b"\x28\xb5\x2f\xfd")
        n = 0
        while i >= 0 and n < 20 and used < budget:
            try:
                with dctx.stream_reader(io.BytesIO(buf[i:])) as r:
                    d = r.read(budget - used)
                if len(d) > 64:
                    out.append((f"zstd@{i:x}", d))
                    used += len(d)
            except Exception:
                pass
            n += 1
            i = buf.find(b"\x28\xb5\x2f\xfd", i + 4)
    except ImportError:
        pass
    if len(buf) <= 40_000_000:
        tries = 0
        for m in re.finditer(rb"\x78[\x01\x5e\x9c\xda]|\x1f\x8b\x08", buf):
            if tries > 3000 or used > budget:
                break
            tries += 1
            i = m.start()
            try:
                z = zlib.decompressobj(31 if buf[i] == 0x1F else 15)
                d = z.decompress(buf[i:i + 30_000_000], 30_000_000)
                if len(d) > 256 and (z.eof or len(d) > 4096):
                    out.append((f"zlib@{i:x}", d))
                    used += len(d)
            except Exception:
                pass
    return out


# ------------------------------------------------------------------------------- stealer extractor
EXFIL = [
    ("discord_webhook", re.compile(rb"https?://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api/(?:v\d+/)?webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,72}")),
    ("telegram_bot", re.compile(rb"(?<![\d])\d{8,10}:AA[A-Za-z0-9_\-]{33}(?![A-Za-z0-9_\-])")),
    ("telegram_api", re.compile(rb"https?://api\.telegram\.org/bot[^\s\"'<>]{0,80}")),
    ("discord_bot_token", re.compile(rb"(?<![A-Za-z0-9_\-])[MNO][A-Za-z\d_\-]{23,25}\.[A-Za-z\d_\-]{6}\.[A-Za-z\d_\-]{27,38}(?![A-Za-z0-9_\-])")),
    ("file_upload", re.compile(rb"https?://(?:[a-z0-9\-]+\.)?(?:gofile\.io|api\.gofile\.io|transfer\.sh|file\.io|anonfiles\.com|catbox\.moe|litterbox\.catbox\.moe|0x0\.st|tmpfiles\.org|bashupload\.com|pixeldrain\.com/api|uguu\.se)[^\s\"'<>]{0,80}", re.I)),
    ("paste", re.compile(rb"https?://(?:pastebin\.com/raw|paste\.ee/r|hastebin\.com/raw|rentry\.co|ghostbin\.\w+)/[^\s\"'<>]{1,60}", re.I)),
    ("tunnel", re.compile(rb"[a-z0-9\-]+\.(?:ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|loca\.lt|serveo\.net|duckdns\.org|ddns\.net|no-ip\.\w+|hopto\.org)", re.I)),
    ("request_bin", re.compile(rb"https?://(?:webhook\.site|[a-z0-9]+\.m\.pipedream\.net|requestbin\.\w+|[a-z0-9]+\.oast\.\w+)/?[^\s\"'<>]{0,60}", re.I)),
    ("ftp_creds", re.compile(rb"ftp://[^\s:/@\"']+:[^\s@\"']+@[^\s/\"']+", re.I)),
    ("smtp", re.compile(rb"smtp\.[a-z0-9\-]+\.[a-z.]{2,10}", re.I)),
]
TARGETS = {
    "browser": rb"Login Data|Local State|Web Data|Network\\\\?Cookies|logins\.json|key4\.db|cookies\.sqlite|\\Google\\Chrome\\User Data|BraveSoftware|Opera Software|Yandex\\YandexBrowser",
    "discord": rb"discord(?:canary|ptb)?\\\\?Local Storage|dQw4w9WgXcQ:|Lightcord|discord\.com/api/v\d+/users/@me",
    "crypto_wallet": rb"wallet\.dat|\\Exodus\\|exodus\.wallet|\\Electrum\\|Atomic\\Local Storage|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|ibnejdfjmmkpcnlpebklmnkoeoihofec|Coinomi|Guarda|Armory|Jaxx|Zcash|Bytecoin|MetaMask",
    "telegram": rb"Telegram Desktop\\\\?tdata|\\tdata\\|key_datas",
    "steam": rb"loginusers\.vdf|\\Steam\\config|ssfn",
    "games": rb"\.ROBLOSECURITY|RobloxCookies|launcher_accounts\.json|\\\.minecraft\\|Growtopia|EpicGamesLauncher|Battle\.net|Riot Client",
    "ftp_vpn": rb"FileZilla\\\\?recentservers|sitemanager\.xml|NordVPN|ProtonVPN|OpenVPN Connect|WinSCP",
    "recon": rb"ip-api\.com|ipinfo\.io|api\.ipify\.org|ipwho\.is|wmic csproduct get uuid|checkip\.amazonaws|myexternalip|geolocation-db",
    "anti_analysis": rb"WDAGUtilityAccount|VBoxService|vmtoolsd|vboxtray|7AB5C494-39F5-4941-9163-47F54D6D5016|Wireshark|HTTP Debugger|fiddler|x64dbg|processhacker|ida64|ollydbg|Sandboxie|VirtualBox|VMware",
    "screen_cam": rb"ImageGrab|CopyFromScreen|BitBlt|webcam|capCreateCaptureWindow|screenshot\.png",
    "clipboard": rb"pyperclip|GetClipboardData|SetClipboardData|Clipboard\.SetText",
}
TARGETS = {k: re.compile(v, re.I) for k, v in TARGETS.items()}
FAMILIES = [
    ("Blank Grabber", rb"Blank Grabber|BlankOBF|blank\.aes"), ("Empyrean", rb"Empyrean"), ("Luna Grabber", rb"Luna[- ]?Grabber|LunaGrabber"),
    ("Creal Stealer", rb"Creal ?Stealer|creal"), ("Umbral Stealer", rb"Umbral ?Stealer|Umbral\."), ("Hazard Token Grabber", rb"Hazard ?Token|Rdimo"),
    ("PySilon", rb"PySilon|pysilon"), ("Wasp Stealer", rb"W4SP|Wasp ?Stealer"), ("Doenerium", rb"Doenerium"), ("Skuld", rb"skuld"),
    ("Exela Stealer", rb"Exela"), ("Rose Grabber", rb"Rose[- ]?Grabber"), ("Cookie Stealer (rookiepy)", rb"rookiepy"), ("Ben Grabber", rb"Ben[- ]?Grabber"),
    ("Kematian", rb"Kematian"), ("Hyperion (obfuscator)", rb"Hyperion"), ("PyArmor (obfuscator)", rb"pyarmor_runtime|pytransform"),
]
FAMILIES = [(n, re.compile(r, re.I)) for n, r in FAMILIES]


def utf16_ascii(buf):
    """UTF-16LE strings (.NET #US heap, Windows APIs) folded to plain bytes so the same regexes match."""
    return b"\n".join(m.group().replace(b"\0", b"") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", buf))


B64 = re.compile(rb"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])")


def b64_layers(blob, cap=400):
    out = []
    for m in B64.finditer(blob[:20_000_000]):
        if len(out) >= cap:
            break
        try:
            d = base64.b64decode(m.group(), validate=True)
        except Exception:
            continue
        if sum(32 <= c < 127 for c in d[:200]) > 0.85 * min(len(d), 200):
            out.append(d)
    return b"\n".join(out)


def extract(sources):
    exfil, seen, targets, fams = [], set(), {}, []
    for where, blob in sources:
        texts = [blob, utf16_ascii(blob) if len(blob) < 60_000_000 else b""]
        texts.append(b64_layers(texts[0] + b"\n" + texts[1]))
        for t in texts:
            if not t:
                continue
            for kind, rx in EXFIL:
                for m in rx.finditer(t):
                    v = m.group().decode("latin-1")[:300]
                    if (kind, v) in seen or len(exfil) >= 40:
                        continue
                    seen.add((kind, v))
                    exfil.append({"kind": kind, "value": v, "source": where})
            for cat, rx in TARGETS.items():
                ex = targets.setdefault(cat, [])
                if len(ex) < 6:
                    for m in rx.finditer(t):
                        s = m.group().decode("latin-1")
                        if s not in ex:
                            ex.append(s)
                        if len(ex) >= 6:
                            break
            for name, rx in FAMILIES:
                if name not in fams and rx.search(t):
                    fams.append(name)
    targets = {k: v for k, v in targets.items() if v}
    steal = [k for k in ("browser", "discord", "crypto_wallet", "telegram", "steam", "games", "ftp_vpn") if k in targets]
    strong_exfil = [e for e in exfil if e["kind"] in ("discord_webhook", "telegram_bot", "telegram_api", "file_upload", "request_bin", "ftp_creds")]
    known = [f for f in fams if "obfuscator" not in f]
    level = "stealer" if known or (strong_exfil and len(steal) >= 2) else "likely" if (strong_exfil and steal) or len(steal) >= 3 else "exfil_only" if strong_exfil else "none"
    return {"exfil": exfil, "targets": targets, "steal_categories": steal, "families": fams, "level": level}


# ---------------------------------------------------------------------------------------- formats
def do_ole(path):
    try:
        from oletools.olevba import VBA_Parser
        vp = VBA_Parser(path)
        if not vp.detect_vba_macros():
            return {"macros": False}, b""
        code = b"\n".join((c or "").encode("latin-1", "replace") for (_, _, _, c) in vp.extract_macros())
        kw = [{"type": t, "keyword": k, "description": d[:160]} for (t, k, d) in vp.analyze_macros()][:60]
        return {"macros": True, "keywords": kw, "autoexec": [k["keyword"] for k in kw if k["type"] == "AutoExec"],
                "suspicious": [k["keyword"] for k in kw if k["type"] == "Suspicious"][:25], "iocs": [k["keyword"] for k in kw if k["type"] == "IOC"][:25],
                "code_lines": code.count(b"\n")}, code
    except Exception as e:
        return {"error": str(e)[:160]}, b""


DANGEROUS = {"SEND_SMS", "READ_SMS", "RECEIVE_SMS", "READ_CONTACTS", "READ_CALL_LOG", "PROCESS_OUTGOING_CALLS", "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION",
             "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "READ_PHONE_STATE", "QUERY_ALL_PACKAGES", "MANAGE_EXTERNAL_STORAGE", "WRITE_SETTINGS",
             "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN", "BIND_NOTIFICATION_LISTENER_SERVICE", "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", "GET_ACCOUNTS",
             "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "RECEIVE_BOOT_COMPLETED", "USE_CREDENTIALS", "CALL_PHONE", "ANSWER_PHONE_CALLS"}


def do_apk(path):
    from loguru import logger
    logger.remove()
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    a = APK(path)
    perms = sorted(set(a.get_permissions()))
    short = lambda p: p.rsplit(".", 1)[-1]
    svc_perms = []
    try:
        xml = a.get_android_manifest_axml().get_xml()
        svc_perms = sorted(set(re.findall(rb'android:permission="android\.permission\.(BIND_[A-Z_]+)"', xml)))
        svc_perms = [s.decode() for s in svc_perms]
    except Exception:
        pass
    certs = []
    for c in a.get_certificates()[:3]:
        try:
            certs.append({"subject": c.subject.human_friendly, "issuer": c.issuer.human_friendly, "sha256": c.sha256.hex() if isinstance(c.sha256, bytes) else str(c.sha256),
                          "debug": "Android Debug" in c.subject.human_friendly})
        except Exception:
            pass
    files = a.get_files()
    libs = sorted({f.split("/")[-1] for f in files if f.startswith("lib/") and f.endswith(".so")})[:60]
    abis = sorted({f.split("/")[1] for f in files if f.startswith("lib/") and f.count("/") >= 2})
    fw = [n for n, rx in (("Unity", r"libunity\.so|libil2cpp\.so"), ("Flutter", r"libflutter\.so"), ("React Native", r"libreactnativejni|libhermes"),
                          ("Xamarin", r"libmonodroid|libxamarin"), ("Mod Menu (LGL)", r"libModMenu|libLGL|libmenu\.so"), ("Frida gadget", r"frida"),
                          ("Il2Cpp", r"libil2cpp\.so")) if any(re.search(rx, l, re.I) for l in libs)]
    strings = []
    for dex in a.get_all_dex():
        try:
            strings.extend(DEX(dex).get_strings())
        except Exception:
            pass
    blob = "\n".join(str(s) for s in strings[:400_000]).encode("utf-8", "replace")
    urls = sorted(set(m.decode("latin-1") for m in re.findall(rb"https?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[^\s\"'<>]{0,80})?", blob)))[:60]
    return {
        "package": a.get_package(), "app_name": a.get_app_name(), "version": a.get_androidversion_name(), "version_code": a.get_androidversion_code(),
        "min_sdk": a.get_min_sdk_version(), "target_sdk": a.get_target_sdk_version(),
        "permissions": [short(p) for p in perms][:80], "dangerous": sorted({short(p) for p in perms if short(p) in DANGEROUS} | set(svc_perms)),
        "activities": len(a.get_activities()), "services": len(a.get_services()), "receivers": len(a.get_receivers()), "providers": len(a.get_providers()),
        "main_activity": a.get_main_activity(), "certificates": certs, "native_libs": libs, "abis": abis, "frameworks": fw, "urls": urls,
        "dex_count": len(list(a.get_all_dex())),
    }, blob


def jadx(sha, path):
    out = os.path.join(WORK, sha, "jadx")
    run([ROOT + "/jadx/bin/jadx", "-d", out, "--no-res", "-j", "4", "--show-bad-code", path], 420)


# ---------------------------------------------------------------------------------------- pipeline
def analyze(sha, name):
    work = os.path.join(WORK, sha)
    path = os.path.join(work, "sample")
    t0 = time.time()
    try:
        with slots:
            buf = open(path, "rb").read()
            kind = kind_of(buf, name)
            res = {"status": "done", "kind": kind, "size": len(buf)}
            res["ssdeep"] = ppdeep.hash(buf)
            th = tlsh.hash(buf)
            res["tlsh"] = th if th and th != "TNULL" else None
            res["yara"] = do_yara(buf)
            res["die"] = do_die(path)
            if kind == "pe":
                res["signature"] = do_sign(path)
            threads, box = [], {}
            pyi, blobs = pyinstaller(buf) if kind == "pe" else (None, [])
            # PyInstaller's bootloader is the same for every app: capa/FLOSS would only describe it, the script is in the archive.
            native = not pyi
            if native and kind in ("pe", "elf") and len(buf) <= 25_000_000:
                threads.append(threading.Thread(target=lambda: box.__setitem__("capa", do_capa(path))))
            if native and kind == "pe" and len(buf) <= 3_000_000:
                threads.append(threading.Thread(target=lambda: box.__setitem__("floss", do_floss(path))))
            for t in threads:
                t.start()
            sources = [("file", buf)]
            if kind == "pe":
                if pyi:
                    res["pyinstaller"] = pyi
                    sources += blobs
                else:
                    sources += compressed_streams(buf)
            elif kind in ("ole", "ooxml"):
                res["office"], code = do_ole(path)
                if code:
                    sources.append(("macro", code))
            elif kind == "apk":
                try:
                    res["apk"], dexstr = do_apk(path)
                    sources.append(("dex", dexstr))
                except Exception as e:
                    res["apk"] = {"error": str(e)[:200]}
            for t in threads:
                t.join()
            res.update(box)
            if box.get("floss", {}).get("status") == "done":
                f = box["floss"]
                sources.append(("floss", "\n".join(f["decoded"] + f["stack"] + f["tight"]).encode("utf-8", "replace")))
            res["stealer"] = extract(sources)
            res["seconds"] = round(time.time() - t0, 1)
        with lock:
            state[sha] = {"status": "done", "t": time.time(), "result": res}
        if kind == "apk":
            jadx(sha, path)
    except Exception as e:
        with lock:
            state[sha] = {"status": "error", "t": time.time(), "error": str(e)[:300]}
        print(f"analyze {sha} failed: {e}", file=sys.stderr, flush=True)
    finally:
        if not os.path.isdir(os.path.join(work, "jadx")):
            try:
                os.remove(path)
            except OSError:
                pass
    print(f"analyze {sha[:12]} {time.time() - t0:.1f}s", file=sys.stderr, flush=True)


def sweep():
    while True:
        time.sleep(300)
        cut = time.time() - 7200
        with lock:
            for s in [s for s, v in state.items() if v["t"] < cut and v["status"] != "running"]:
                state.pop(s, None)
        for d in os.listdir(WORK):
            p = os.path.join(WORK, d)
            if SHA_RE.match(d) and os.path.getmtime(p) < cut and state.get(d, {}).get("status") != "running":
                shutil.rmtree(p, ignore_errors=True)


def similar(body):
    h, s, hits = body.get("tlsh"), body.get("ssdeep"), []
    for item in body.get("items", [])[:20000]:
        jid, t2, s2 = item[0], item[1], item[2] if len(item) > 2 else None
        d = tlsh.diff(h, t2) if h and t2 else None
        sc = ppdeep.compare(s, s2) if s and s2 else 0
        if (d is not None and d <= 120) or sc >= 40:
            hits.append([jid, d, sc])
    hits.sort(key=lambda x: (x[1] if x[1] is not None else 999) - x[2])
    return {"hits": hits[:50]}


class H(BaseHTTPRequestHandler):
    def ok(self):
        if not hmac.compare_digest(self.headers.get("Authorization", ""), f"Token {TOKEN}"):
            self.reply({"error": "auth"}, 401)
            return False
        return True

    def reply(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self, cap):
        n = int(self.headers.get("Content-Length", "0"))
        if n > cap:
            raise ValueError("too_large")
        return self.rfile.read(n)

    def do_POST(self):
        if not self.ok():
            return
        u = urlsplit(self.path)
        try:
            if u.path == "/similar":
                return self.reply(similar(json.loads(self.body(20_000_000))))
            m = re.match(r"^/analyze/([0-9a-f]{64})$", u.path)
            if not m:
                return self.reply({"error": "not_found"}, 404)
            sha = m.group(1)
            with lock:
                cur = state.get(sha)
                if cur and cur["status"] in ("running", "done"):
                    return self.reply({"status": cur["status"]})
                state[sha] = {"status": "running", "t": time.time()}
            data = self.body(160 * 1024 * 1024)
            if hashlib.sha256(data).hexdigest() != sha:
                with lock:
                    state.pop(sha, None)
                return self.reply({"error": "sha_mismatch"}, 400)
            os.makedirs(os.path.join(WORK, sha), exist_ok=True)
            with open(os.path.join(WORK, sha, "sample"), "wb") as f:
                f.write(data)
            try:
                name = base64.b64decode(self.headers.get("X-Name", "")).decode("utf-8", "replace")[:200]
            except Exception:
                name = ""
            threading.Thread(target=analyze, args=(sha, name), daemon=True).start()
            self.reply({"status": "running"})
        except ValueError as e:
            self.reply({"error": str(e)}, 413)

    def do_GET(self):
        if not self.ok():
            return
        u = urlsplit(self.path)
        q = parse_qs(u.query)
        m = re.match(r"^/result/([0-9a-f]{64})$", u.path)
        if m:
            with lock:
                st = state.get(m.group(1))
            if not st:
                return self.reply({"status": "missing"}, 404)
            return self.reply(st.get("result") or {"status": st["status"], "error": st.get("error")})
        m = re.match(r"^/apk/([0-9a-f]{64})/(search|source)$", u.path)
        if m:
            root = os.path.join(WORK, m.group(1), "jadx", "sources")
            if not os.path.isdir(root):
                return self.reply({"error": "no_jadx"}, 404)
            if m.group(2) == "search":
                try:
                    rx = re.compile(q.get("q", [""])[0][:200], re.I)
                except re.error:
                    return self.reply({"error": "bad_regex"}, 400)
                hits = []
                for dp, _, fs in os.walk(root):
                    for fn in fs:
                        p = os.path.join(dp, fn)
                        try:
                            for i, line in enumerate(open(p, encoding="utf-8", errors="replace"), 1):
                                if rx.search(line):
                                    hits.append({"file": os.path.relpath(p, root), "line": i, "text": line.strip()[:200]})
                                    if len(hits) >= 80:
                                        return self.reply({"hits": hits, "truncated": True})
                        except OSError:
                            pass
                return self.reply({"hits": hits})
            rel = os.path.normpath(q.get("path", [""])[0]).lstrip("/")
            p = os.path.join(root, rel)
            if rel.startswith("..") or not os.path.isfile(p):
                return self.reply({"error": "no_file"}, 404)
            return self.reply({"path": rel, "text": open(p, encoding="utf-8", errors="replace").read(60000)})
        self.reply({"error": "not_found"}, 404)

    def log_message(self, *a):
        pass


os.makedirs(WORK, exist_ok=True)
threading.Thread(target=sweep, daemon=True).start()
print("cg-static listening on 127.0.0.1:8005", file=sys.stderr, flush=True)
ThreadingHTTPServer(("127.0.0.1", 8005), H).serve_forever()
