# ClashGear Token Tuzağı (bait profile). Enabled only by the task option cghoney=<base64url JSON> that the
# ClashGear backend builds for each run (every value is unique to that run and fake).
#
# start():  before the sample starts, writes the bait accounts into this user's profile: Discord leveldb,
#           Chromium Login Data / Cookies (encrypted with this guest's own DPAPI key, so a stealer really can
#           decrypt them), Steam ssfn, Telegram tdata, Exodus / MetaMask wallets, a Roblox cookie, a note on the
#           desktop; then puts a SACL on every bait file so Windows logs who opened it for reading (event 4663,
#           kernel-side: also works when the sample shakes off CAPE's monitor), and starts a clipboard watcher
#           that keeps a fake crypto address on the clipboard and notes when something swaps it.
# finish(): collects the read events, searches files created during the run (zip/archives included) for the
#           bait values, and uploads aux/cghoney_report.json for the backend (via cg-files /honey/<task>).
import base64
import ctypes
import json
import logging
import os
import sqlite3
import subprocess
import threading
import time
import winreg
import zipfile
import re
import zlib
from ctypes import wintypes
from xml.etree import ElementTree

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

# Readers that are Windows (or the analyzer) itself, never the sample.
SELF_READERS = ("\\python.exe", "\\pythonw.exe", "\\searchprotocolhost.exe", "\\searchindexer.exe", "\\searchfilterhost.exe",
                "\\msmpeng.exe", "\\mpcmdrun.exe", "\\wevtutil.exe", "\\perfhostsvc.exe", "\\auditpol.exe")
SCAN_MAX_FILES = 4000
SCAN_MAX_SIZE = 40 * 1024 * 1024
COLLECT_EVERY = 20
# What a clipper pastes in: an address of its own (CAPE's human module also puts random words on the clipboard).
CRYPTO_ADDR = re.compile(r"^(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[0-9a-fA-F]{40}|T[1-9A-HJ-NP-Za-km-z]{33}|[LM][a-km-zA-HJ-NP-Z1-9]{26,33}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}|[1-9A-HJ-NP-Za-km-z]{32,44})$")
SKIP_DIRS = ("\\microsoft\\windows\\inetcache", "\\cache\\cache_data", "\\code cache", "\\gpucache", "\\packages\\microsoft.",
             "\\microsoft\\windows\\webcache", "\\programdata\\microsoft", "\\appdata\\local\\microsoft\\windows\\explorer")


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_protect(data):
    buf = ctypes.create_string_buffer(data, len(data))
    inp = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    crypt32.CryptProtectData.argtypes = [ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
    if not crypt32.CryptProtectData(ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


class Clipboard:
    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x2

    def __init__(self):
        u, k = ctypes.windll.user32, ctypes.windll.kernel32
        u.OpenClipboard.argtypes = [wintypes.HWND]
        u.GetClipboardData.restype = wintypes.HANDLE
        u.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
        u.SetClipboardData.restype = wintypes.HANDLE
        k.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        k.GlobalAlloc.restype = wintypes.HGLOBAL
        k.GlobalLock.argtypes = [wintypes.HGLOBAL]
        k.GlobalLock.restype = ctypes.c_void_p
        k.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        self.u, self.k = u, k

    def _open(self):
        for _ in range(20):
            if self.u.OpenClipboard(None):
                return True
            time.sleep(0.05)
        return False

    def set(self, text):
        if not self._open():
            return False
        try:
            self.u.EmptyClipboard()
            raw = (text + "\0").encode("utf-16-le")
            h = self.k.GlobalAlloc(self.GMEM_MOVEABLE, len(raw))
            p = self.k.GlobalLock(h)
            ctypes.memmove(p, raw, len(raw))
            self.k.GlobalUnlock(h)
            return bool(self.u.SetClipboardData(self.CF_UNICODETEXT, h))
        finally:
            self.u.CloseClipboard()

    def get(self):
        if not self._open():
            return None
        try:
            h = self.u.GetClipboardData(self.CF_UNICODETEXT)
            if not h:
                return ""
            p = self.k.GlobalLock(h)
            try:
                return ctypes.wstring_at(p)
            finally:
                self.k.GlobalUnlock(h)
        finally:
            self.u.CloseClipboard()


class CGHoney(Auxiliary):
    """ClashGear Token Tuzağı: fake accounts in the guest profile, and who touched them."""

    start_priority = 5

    def __init__(self, options=None, config=None):
        Auxiliary.__init__(self, options, config)
        raw = (options or {}).get("cghoney", "")
        self.spec = None
        if raw:
            try:
                self.spec = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
            except Exception as e:  # noqa: BLE001
                log.warning("cg_honey: bad spec: %s", e)
        self.report = {"v": 1, "errors": [], "baits": [], "reads": [], "packed": [], "clipboard": [], "audit": False}
        self.started = time.time()
        self.stop_clip = threading.Event()
        self.clip_thread = None
        self.paths = {}  # absolute lower-case path -> bait id
        self.lock = threading.Lock()
        self.read_seen = set()
        self.pack_seen = {}  # path -> (mtime, size) already scanned
        self.packed = {}
        self.final = False

    # --- setup -----------------------------------------------------------------------------------------
    def _err(self, what, e):
        log.warning("cg_honey: %s: %s", what, e)
        self.report["errors"].append(f"{what}: {e}"[:300])

    def _path(self, p):
        return os.path.abspath(os.path.expandvars(p))

    def _note(self, path, bait):
        self.paths[path.lower()] = bait
        self.report["baits"].append({"id": bait, "path": path})

    def _write(self, item):
        path = self._path(item["p"])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(base64.b64decode(item["b64"]))
        if item.get("bait"):
            self._note(path, item["bait"])

    def _local_state(self, item):
        path = self._path(item["p"])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        enc = base64.b64encode(b"DPAPI" + dpapi_protect(bytes.fromhex(item["key"]))).decode()
        state = item.get("extra") or {}
        state["os_crypt"] = {"encrypted_key": enc}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f)
        if item.get("bait"):
            self._note(path, item["bait"])

    def _sqlite(self, item):
        path = self._path(item["p"])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            os.remove(path)
        db = sqlite3.connect(path)
        try:
            db.executescript(item["schema"])
            for row in item["rows"]:
                cols = list(row.keys())
                vals = [base64.b64decode(v[4:]) if isinstance(v, str) and v.startswith("b64:") else v for v in row.values()]
                db.execute(f"INSERT INTO {item['table']} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", vals)
            db.commit()
        finally:
            db.close()
        self._note(path, item["bait"])

    def _reg(self, item):
        root = winreg.HKEY_CURRENT_USER if item["k"].upper().startswith("HKCU\\") else winreg.HKEY_LOCAL_MACHINE
        sub = item["k"].split("\\", 1)[1]
        with winreg.CreateKeyEx(root, sub, 0, winreg.KEY_WRITE) as k:
            winreg.SetValueEx(k, item["n"], 0, winreg.REG_DWORD if isinstance(item["v"], int) else winreg.REG_SZ, item["v"])

    def _audit(self):
        # File System object-access auditing (subcategory GUID: language independent) + a SACL "Everyone, ReadData,
        # Success" on every bait file. Straight through the Win32 API (a cold PowerShell took ~80 s in the guest);
        # PowerShell stays as the fallback.
        subprocess.run(["auditpol", "/set", "/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}", "/success:enable"],
                       capture_output=True, timeout=30, creationflags=0x08000000)
        try:
            n = self._audit_native()
            self.report["audit"] = n > 0
            if n == len(self.paths_original):
                return
        except Exception as e:  # noqa: BLE001
            self._err("audit native", e)
        self._audit_ps()

    def _audit_native(self):
        adv, k32 = ctypes.WinDLL("advapi32", use_last_error=True), ctypes.windll.kernel32

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        k32.GetCurrentProcess.restype = wintypes.HANDLE
        adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        adv.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
        adv.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
        adv.GetSecurityDescriptorSacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
        adv.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        adv.SetNamedSecurityInfoW.restype = wintypes.DWORD

        tok = wintypes.HANDLE()
        if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0028, ctypes.byref(tok)):  # ADJUST_PRIVILEGES | QUERY
            raise ctypes.WinError()
        luid = LUID()
        if not adv.LookupPrivilegeValueW(None, "SeSecurityPrivilege", ctypes.byref(luid)):
            raise ctypes.WinError()
        tp = TOKEN_PRIVILEGES(1, (LUID_AND_ATTRIBUTES * 1)(LUID_AND_ATTRIBUTES(luid, 2)))
        adv.AdjustTokenPrivileges(tok, False, ctypes.byref(tp), 0, None, None)
        if ctypes.get_last_error() == 1300:  # ERROR_NOT_ALL_ASSIGNED: not elevated
            raise OSError("SeSecurityPrivilege not held")
        sd, sacl = ctypes.c_void_p(), ctypes.c_void_p()
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW("S:(AU;SA;0x1;;;WD)", 1, ctypes.byref(sd), None):
            raise ctypes.WinError()
        adv.GetSecurityDescriptorSacl(sd, ctypes.byref(present), ctypes.byref(sacl), ctypes.byref(defaulted))
        n = 0
        for p in self.paths_original:
            rc = adv.SetNamedSecurityInfoW(p, 1, 0x8, None, None, None, sacl)  # SE_FILE_OBJECT, SACL_SECURITY_INFORMATION
            if rc == 0:
                n += 1
            else:
                self.report["errors"].append(f"sacl {rc} {p}"[:300])
        k32.LocalFree(sd)
        return n

    def _audit_ps(self):
        listing = os.path.join(os.environ.get("TEMP", "C:\\Windows\\Temp"), "cgh_paths.txt")
        with open(listing, "w", encoding="utf-8") as f:
            f.write("\n".join(self.paths_original))
        ps = (
            "$ErrorActionPreference='Continue';"
            "auditpol /set /subcategory:'{0CCE921D-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null;"
            "$sid=New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0');"
            "$rule=New-Object System.Security.AccessControl.FileSystemAuditRule($sid,'ReadData','None','None','Success');"
            f"$n=0; foreach($p in Get-Content -LiteralPath '{listing}' -Encoding UTF8){{ try {{ $a=Get-Acl -LiteralPath $p -Audit; $a.AddAuditRule($rule); Set-Acl -LiteralPath $p -AclObject $a; $n++ }} catch {{ Write-Output ('ERR '+$p+' '+$_) }} }};"
            "Write-Output ('OK '+$n)"
        )
        r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps],
                           capture_output=True, text=True, timeout=90, creationflags=0x08000000)
        out = (r.stdout or "") + (r.stderr or "")
        try:
            os.remove(listing)
        except OSError:
            pass
        ok = [ln for ln in out.splitlines() if ln.startswith("OK ")]
        self.report["audit"] = bool(ok) and ok[-1] != "OK 0"
        for ln in out.splitlines():
            if ln.startswith("ERR"):
                self.report["errors"].append(ln[:300])

    def start(self):
        if not self.spec:
            return True
        spec = self.spec
        for kind, fn in (("files", self._write), ("local_state", self._local_state), ("sqlite", self._sqlite), ("reg", self._reg)):
            for item in spec.get(kind, []):
                try:
                    fn(item)
                except Exception as e:  # noqa: BLE001
                    self._err(f"{kind} {item.get('p') or item.get('k')}", e)
        self.paths_original = [b["path"] for b in self.report["baits"]]
        try:
            self._audit()
        except Exception as e:  # noqa: BLE001
            self._err("audit", e)
        if spec.get("clip"):
            self.clip_thread = threading.Thread(target=self._clip_loop, daemon=True)
            self.clip_thread.start()
        threading.Thread(target=self._collect_loop, daemon=True).start()
        log.info("cg_honey: %d bait files placed, audit=%s", len(self.report["baits"]), self.report["audit"])
        self.started = time.time()
        return True

    # --- clipboard watcher -------------------------------------------------------------------------------
    def _clip_loop(self):
        try:
            cb = Clipboard()
        except Exception as e:  # noqa: BLE001
            return self._err("clipboard", e)
        addrs = self.spec["clip"]
        i = 0
        while not self.stop_clip.is_set() and len(self.report["clipboard"]) < 10:
            want = addrs[i % len(addrs)]
            i += 1
            try:
                cb.set(want)
                # clippers react to the clipboard-change notification or poll every few hundred ms
                if self.stop_clip.wait(2.5):
                    break
                got = cb.get()
                if got is not None and got.strip() != want and CRYPTO_ADDR.match(got.strip()):
                    self.report["clipboard"].append({"expected": want, "got": got.strip()[:200], "t": round(time.time() - self.started, 1)})
            except Exception as e:  # noqa: BLE001
                self._err("clipboard", e)
                if self.stop_clip.wait(5):
                    break
            if self.stop_clip.wait(5):
                break

    # --- collection ------------------------------------------------------------------------------------
    # Collected during the run, not only at the end: after the timeout the host gives the guest a few seconds
    # before it pulls the plug, so a snapshot goes up every COLLECT_EVERY seconds and a final one at stop().
    def _collect_loop(self):
        n = 0
        while not self.stop_clip.wait(COLLECT_EVERY):
            n += 1
            self._collect(budget=10)
            self._upload(f"cghoney_report_{n:03d}.json")

    def _collect(self, budget):
        with self.lock:
            t0 = time.time()
            for what, fn in (("reads", self._reads), ("packed", lambda: self._packed(t0 + budget))):
                try:
                    fn()
                except Exception as e:  # noqa: BLE001
                    self._err(what, e)

    def _upload(self, name):
        with self.lock:
            self.report["packed"] = list(self.packed.values())[:60]
            self.report["collected_at"] = round(time.time() - self.started, 1)
            path = os.path.join(os.environ.get("TEMP", "C:\\Windows\\Temp"), name)
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self.report, f)
                upload_to_host(path, f"aux/{name}")
                os.remove(path)
                return True
            except Exception as e:  # noqa: BLE001
                log.warning("cg_honey: upload %s failed: %s", name, e)
                return False

    def stop(self):
        if not self.spec:
            return True
        self.stop_clip.set()
        self._collect(budget=5)
        self.final = self._upload("cghoney_report_final.json")
        return True

    def _reads(self):
        r = subprocess.run(["wevtutil", "qe", "Security", "/q:*[System[(EventID=4663)]]", "/f:xml", "/c:5000"],
                           capture_output=True, timeout=30, creationflags=0x08000000)
        text = r.stdout.decode("utf-8", "replace")
        ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        for chunk in text.split("</Event>"):
            if "<Event" not in chunk or len(self.report["reads"]) >= 300:
                continue
            try:
                ev = ElementTree.fromstring(chunk[chunk.index("<Event"):] + "</Event>")
            except ElementTree.ParseError:
                continue
            d = {x.get("Name"): (x.text or "") for x in ev.iter(ns + "Data")}
            obj, proc = d.get("ObjectName", ""), d.get("ProcessName", "")
            bait = self.paths.get(obj.lower())
            if not bait or proc.lower().endswith(SELF_READERS):
                continue
            # Explorer reads a desktop text file to draw it; that is not the sample.
            if bait == "note" and proc.lower().endswith("\\explorer.exe"):
                continue
            key = (obj.lower(), proc.lower())
            if key in self.read_seen:
                continue
            self.read_seen.add(key)
            t = ev.find(f"{ns}System/{ns}TimeCreated")
            pid = d.get("ProcessId", "")
            self.report["reads"].append({"bait": bait, "path": obj, "process": proc, "pid": int(pid, 16) if pid.startswith("0x") else pid,
                                         "time": t.get("SystemTime") if t is not None else None})

    def _markers(self):
        out = []
        for m in self.spec.get("markers", []):
            s = m["s"].encode()
            out.append((m["id"], (s, m["s"].encode("utf-16-le"))))
        return out

    def _hits(self, data, markers):
        return [mid for mid, forms in markers if any(f in data for f in forms)]

    def _scan_blob(self, data, markers, depth=0):
        """Marker ids found in a file's bytes, looking inside zip archives and zlib/gzip streams too."""
        hits = set(self._hits(data, markers))
        members = []
        if depth < 2 and data[:4] == b"PK\x03\x04":
            try:
                import io
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    for info in z.infolist()[:400]:
                        if info.file_size > SCAN_MAX_SIZE:
                            continue
                        try:
                            inner = z.read(info)
                        except Exception:  # noqa: BLE001 (encrypted or broken member)
                            members.append({"name": info.filename[:200], "locked": True})
                            continue
                        h, _ = self._scan_blob(inner, markers, depth + 1)
                        if h:
                            hits |= set(h)
                            members.append({"name": info.filename[:200], "markers": sorted(h)})
            except Exception:  # noqa: BLE001
                pass
        elif depth < 2 and data[:2] == b"\x1f\x8b":
            try:
                h, _ = self._scan_blob(zlib.decompress(data, 47), markers, depth + 1)
                hits |= set(h)
            except Exception:  # noqa: BLE001
                pass
        return sorted(hits), members

    def _packed(self, deadline):
        markers = self._markers()
        if not markers:
            return
        roots = [os.environ.get("TEMP"), os.environ.get("APPDATA"), os.environ.get("LOCALAPPDATA"), os.environ.get("USERPROFILE"),
                 os.environ.get("PUBLIC"), os.environ.get("ProgramData", "C:\\ProgramData"), "C:\\Windows\\Temp"]
        analyzer = os.path.abspath(os.getcwd()).lower()
        seen, n = set(), 0
        for root in [r for r in roots if r and os.path.isdir(r)]:
            for d, dirs, files in os.walk(root):
                dl = d.lower()
                if dl.startswith(analyzer) or any(x in dl for x in SKIP_DIRS):
                    dirs[:] = []
                    continue
                if time.time() > deadline:
                    return
                for f in files:
                    p = os.path.join(d, f)
                    pl = p.lower()
                    if pl in seen or pl in self.paths:
                        continue
                    seen.add(pl)
                    try:
                        st = os.stat(p)
                    except OSError:
                        continue
                    if max(st.st_mtime, st.st_ctime) < self.started - 2 or st.st_size == 0 or st.st_size > SCAN_MAX_SIZE:
                        continue
                    sig = (st.st_mtime, st.st_size)
                    if self.pack_seen.get(pl) == sig:
                        continue
                    self.pack_seen[pl] = sig
                    n += 1
                    if n > SCAN_MAX_FILES:
                        return
                    try:
                        with open(p, "rb") as fh:
                            data = fh.read()
                    except OSError:
                        continue
                    hits, members = self._scan_blob(data, markers)
                    archive = data[:4] in (b"PK\x03\x04", b"Rar!") or data[:6] == b"7z\xbc\xaf\x27\x1c"
                    if hits:
                        self.packed[pl] = {"path": p, "size": st.st_size, "archive": archive, "markers": hits, "members": members[:40]}
                    elif archive and (data[:4] != b"PK\x03\x04" or any(m.get("locked") for m in members)):
                        # an archive we cannot open (rar/7z/password) made during the run
                        self.packed.setdefault(pl, {"path": p, "size": st.st_size, "archive": True, "markers": [], "unreadable": True})

    def finish(self):
        if self.spec and not self.final:
            self._upload("cghoney_report_final.json")
        return True
