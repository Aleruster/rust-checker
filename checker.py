
import ctypes
import ctypes.wintypes as wintypes
import hashlib
import json
import os
import queue
import re
import shutil
import sqlite3
import struct
import sys
import tempfile
import threading
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from urllib.parse import urlparse, unquote

USB_RECENT_HOURS = 24

MIN_SIZE = 1 * 1024 * 1024
MAX_SIZE = 10 * 1024 * 1024
DEEP_MIN = 256 * 1024
DEEP_MAX = 256 * 1024 * 1024

CHUNK = 4 * 1024 * 1024
BIG_FILE = 8 * 1024 * 1024
SKIP_SECTIONS = {b".rsrc\x00\x00\x00", b".reloc\x00\x00", b".pdata\x00\x00"}

WALKERS = 8
WORKERS = min(32, (os.cpu_count() or 4) * 4)
PROCS = max(2, min(16, os.cpu_count() or 4))

PE_EXT = {".dll", ".exe", ".sys", ".node", ".asi", ".ocx", ".cpl",
          ".drv", ".efi", ".bin", ".dat", ".tmp", ""}
MFT_EXT = {".dll", ".exe", ".sys", ".node", ".asi", ".ocx", ".cpl",
           ".drv", ".efi", ".bin", ".dat", ".tmp"}

SKIP_DIRS = {"winsxs", "servicing", "driverstore", "catroot2",
             "assembly", "installer", "windowsapps", "systemapps"}
SKIP_MARKS = tuple("\\%s\\" % d for d in SKIP_DIRS)

if os.name == "nt":
    try:
        _k = ctypes.windll.kernel32
        _k.SetConsoleMode(_k.GetStdHandle(-11), 7)

        _k.SetConsoleOutputCP(65001)
        _k.SetConsoleCP(65001)
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def _self_paths():

    out, prefixes = set(), []
    for p in (sys.executable, sys.argv[0] if sys.argv else "",
              globals().get("__file__", "")):
        try:
            if p:
                out.add(os.path.normcase(os.path.abspath(p)))
        except (OSError, ValueError):
            pass
    mei = getattr(sys, "_MEIPASS", "")
    if mei:
        prefixes.append(os.path.normcase(os.path.abspath(mei)) + os.sep)
    return out, tuple(prefixes)

SELF_FILES, SELF_DIRS = _self_paths()

def is_self(path):
    try:
        p = os.path.normcase(os.path.abspath(path))
    except (OSError, ValueError):
        return False
    if p in SELF_FILES:
        return True
    return bool(SELF_DIRS) and p.startswith(SELF_DIRS)

R, RED, GRN, YEL, CYN, GRY = ("\033[0m", "\033[91m", "\033[92m",
                              "\033[93m", "\033[96m", "\033[90m")

class Progress:

    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    WIDTH = 28

    def __init__(self, text, enabled=True):
        self.text, self.enabled = text, enabled
        self.frac = 0.0
        self._stop = threading.Event()
        self._t = None

    def set(self, frac):
        self.frac = 0.0 if frac < 0 else (1.0 if frac > 1 else frac)

    def start(self):
        if not self.enabled:
            print(f"  [*] {self.text}")
            return self
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()
        return self

    def _run(self):
        i = 0
        while not self._stop.is_set():
            self._draw(self.FRAMES[i % len(self.FRAMES)])
            i += 1
            time.sleep(0.08)

    def _draw(self, frame):
        done = int(self.frac * self.WIDTH)
        bar = "█" * done + "░" * (self.WIDTH - done)
        sys.stdout.write(f"\r  {CYN}[{frame}]{R} {self.text}  "
                         f"{CYN}{bar}{R} {self.frac * 100:5.1f}%")
        sys.stdout.flush()

    def stop(self):
        if not self.enabled:
            return
        self._stop.set()
        if self._t:
            self._t.join()
        sys.stdout.write("\r" + " " * (self.WIDTH + len(self.text) + 24) + "\r")
        sys.stdout.flush()

def long_path(p):
    if os.name == "nt" and len(p) > 240 and not p.startswith("\\\\?\\"):
        return "\\\\?\\" + p
    return p

def human(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

def list_drives():
    if os.name != "nt":
        return ["/"]
    out = []
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if not mask & (1 << i):
            continue
        root = f"{chr(65 + i)}:\\"
        if ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) in (2, 3):
            out.append(root)
    return out

def fs_name(root):
    fs = ctypes.create_unicode_buffer(16)
    ok = ctypes.windll.kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(root), None, 0, None, None, None, fs, 16)
    return fs.value.upper() if ok else "?"

def is_ntfs(root):
    return fs_name(root) == "NTFS"

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def hot_roots():
    env = os.environ.get
    cands = [env("USERPROFILE", ""), env("TEMP", ""), env("APPDATA", ""),
             env("LOCALAPPDATA", ""), env("PROGRAMDATA", ""), env("PUBLIC", "")]
    for d in list_drives():
        cands += [os.path.join(d, "$Recycle.Bin"), os.path.join(d, "Games"),
                  os.path.join(d, "SteamLibrary", "steamapps", "common", "Rust"),
                  os.path.join(d, "Steam", "steamapps", "common", "Rust")]
    seen, out = set(), []
    for c in cands:
        if c and os.path.isdir(c) and c.lower() not in seen:
            seen.add(c.lower())
            out.append(c)
    return out

class Stats:
    def __init__(self):
        self.dirs = self.cands = self.scanned = self.bytes = 0
        self.lock = threading.Lock()

_k32 = ctypes.WinDLL("kernel32", use_last_error=True) if os.name == "nt" else None
FSCTL_ENUM_USN_DATA = 0x900B3
_INVALID = ctypes.c_void_p(-1).value

if _k32:
    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                 ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                 wintypes.HANDLE]
    _k32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
                                     wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                     ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]

def _name_hit(low):

    dot = low.rfind(".")
    if (low[dot:] if dot > 0 else "") not in PE_EXT:
        return False
    return any(n in low for n in _HINTS["names"])

_DIR_MAPS = {}

def dir_map(vol):

    vol = vol.upper()
    if vol in _DIR_MAPS:
        return _DIR_MAPS[vol]
    h = _k32.CreateFileW("\\\\.\\" + vol, 0x80000000, 3, None, 3, 0, None)
    if h in (_INVALID, -1, 0, None):
        return {}
    dirs = {}
    buf = ctypes.create_string_buffer(1 << 20)
    ret = wintypes.DWORD()
    inp = ctypes.create_string_buffer(struct.pack("<qqq", 0, 0, 2**63 - 1), 24)
    try:
        while True:
            ok = _k32.DeviceIoControl(h, FSCTL_ENUM_USN_DATA, inp, 24, buf,
                                      ctypes.sizeof(buf), ctypes.byref(ret), None)
            if not ok or ret.value <= 8:
                break
            data = buf.raw[:ret.value]
            nxt = struct.unpack_from("<q", data, 0)[0]
            off = 8
            while off < len(data):
                rl = struct.unpack_from("<I", data, off)[0]
                if rl == 0:
                    break
                if struct.unpack_from("<I", data, off + 52)[0] & 0x10:
                    frn, par = struct.unpack_from("<QQ", data, off + 8)
                    fnl, fno = struct.unpack_from("<HH", data, off + 56)
                    dirs[frn] = (data[off + fno:off + fno + fnl]
                                 .decode("utf-16le", "ignore"), par)
                off += rl
            struct.pack_into("<q", inp, 0, nxt)
    finally:
        _k32.CloseHandle(h)
    _DIR_MAPS[vol] = dirs
    return dirs

def resolve_path(vol, frn, name):

    dirs = dir_map(vol)
    parts, hops = [], 0
    while frn in dirs and hops < 64:
        nm, par = dirs[frn]
        if par == frn:
            break
        parts.append(nm)
        frn = par
        hops += 1
    if not parts:
        return None
    return vol.upper() + "\\" + "\\".join(reversed(parts)) + "\\" + name

def enum_mft(root, deep):

    vol = root.rstrip("\\")
    h = _k32.CreateFileW("\\\\.\\" + vol, 0x80000000, 3, None, 3, 0, None)
    if h in (_INVALID, -1, 0, None):
        return None

    dirs, files = {}, []
    buf = ctypes.create_string_buffer(1 << 20)
    ret = wintypes.DWORD()
    inp = ctypes.create_string_buffer(struct.pack("<qqq", 0, 0, 2**63 - 1), 24)
    try:
        while True:
            ok = _k32.DeviceIoControl(h, FSCTL_ENUM_USN_DATA, inp, 24, buf,
                                      ctypes.sizeof(buf), ctypes.byref(ret), None)
            if not ok or ret.value <= 8:
                break
            data = buf.raw[:ret.value]
            nxt = struct.unpack_from("<q", data, 0)[0]
            off = 8
            while off < len(data):
                rl = struct.unpack_from("<I", data, off)[0]
                if rl == 0:
                    break
                frn, par = struct.unpack_from("<QQ", data, off + 8)
                attr = struct.unpack_from("<I", data, off + 52)[0]
                fnl, fno = struct.unpack_from("<HH", data, off + 56)
                name = data[off + fno:off + fno + fnl].decode("utf-16le", "ignore")
                if attr & 0x10:
                    dirs[frn] = (name, par)
                else:
                    dot = name.rfind(".")
                    ext = name[dot:].lower() if dot > 0 else ""
                    if deep or ext in MFT_EXT or _name_hit(name.lower()):
                        files.append((name, par))
                off += rl
            struct.pack_into("<q", inp, 0, nxt)
    finally:
        _k32.CloseHandle(h)

    _DIR_MAPS[vol.upper()] = dirs

    if not files:
        return None

    cache = {}

    def resolve(frn):
        parts, hops = [], 0
        while frn in dirs and hops < 64:
            nm, par = dirs[frn]
            if par == frn:
                break
            parts.append(nm)
            frn = par
            hops += 1
        return vol + "\\" + "\\".join(reversed(parts))

    out = []
    for nm, par in files:
        base = cache.get(par)
        if base is None:
            base = cache[par] = resolve(par)
        out.append(base + "\\" + nm)
    return out

def _walk(dirq, out, deep, stats, bar, share):
    lo = DEEP_MIN if deep else _HINTS["min_size"]
    hi = DEEP_MAX if deep else _HINTS["max_size"]
    while True:
        try:
            d = dirq.get(timeout=0.4)
        except queue.Empty:
            if dirq.unfinished_tasks == 0:
                return
            continue
        try:
            with os.scandir(long_path(d)) as it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if e.name.lower() in SKIP_DIRS:
                                continue

                            if getattr(e.stat(follow_symlinks=False),
                                       "st_file_attributes", 0) & 0x400:
                                continue
                            dirq.put(e.path)
                            with stats.lock:
                                stats.dirs += 1
                                if stats.dirs % 128 == 0:
                                    bar.set(share[0] + share[1] * min(
                                        1.0, stats.dirs / 200000))
                            continue
                        if not e.is_file(follow_symlinks=False):
                            continue
                        name = e.name.lower()
                        hinted = _name_hit(name)
                        if not deep and not hinted\
                                and os.path.splitext(name)[1] not in PE_EXT:
                            continue
                        size = e.stat(follow_symlinks=False).st_size
                        if not hinted and not (lo <= size <= hi):
                            continue
                        with stats.lock:
                            stats.cands += 1
                            out.append((e.path, size))
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            pass
        finally:
            dirq.task_done()

def collect(roots, deep, stats, bar, base, weight):

    lo = DEEP_MIN if deep else _HINTS["min_size"]
    hi = DEEP_MAX if deep else _HINTS["max_size"]
    cands, fallback = [], []
    done_roots = 0

    for root in roots:
        drive = os.path.splitdrive(root)[0] + "\\"
        whole = os.path.normpath(root).rstrip("\\") == drive.rstrip("\\")
        if not (whole and os.name == "nt" and is_ntfs(drive) and is_admin()):
            fallback.append(root)
            continue
        paths = enum_mft(drive, deep)
        if paths is None:
            fallback.append(root)
            continue
        share = weight / len(roots)
        total = max(1, len(paths))
        for i, p in enumerate(paths):
            if i % 512 == 0:
                bar.set(base + done_roots * share + share * i / total)
            low = p.lower()
            hinted = _name_hit(os.path.basename(low))
            if not hinted and any(m in low for m in SKIP_MARKS):
                continue
            try:
                size = os.stat(long_path(p)).st_size
            except OSError:
                continue
            if hinted or lo <= size <= hi:
                cands.append((p, size))
                stats.cands += 1
        done_roots += 1

    if fallback:
        dirq = queue.Queue()
        for d in fallback:
            dirq.put(d)
            stats.dirs += 1
        share = (base + weight * done_roots / max(1, len(roots)),
                 weight * len(fallback) / max(1, len(roots)))
        ws = [threading.Thread(target=_walk,
                               args=(dirq, cands, deep, stats, bar, share),
                               daemon=True) for _ in range(WALKERS)]
        for w in ws:
            w.start()
        for w in ws:
            w.join()
    return cands

def _rva_to_off(sections, rva):
    for _, va, vs, ro, rs in sections:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None

def _read_at(f, off, n):
    try:
        f.seek(off)
        return f.read(n)
    except OSError:
        return b""

def _has_fake_signature(f):
    """Проверяет есть ли в файле цифровая подпись.
    Если подпись есть от Microsoft/Google/Apple — это явно читовский лоадер
    (обычные Windows программы подписаны корректно, подделка — признак читовского лоадера)."""
    try:
        head = _read_at(f, 0, 0x100)
        if head[:2] != b"MZ" or len(head) < 0x40:
            return False
        e = struct.unpack_from("<I", head, 0x3C)[0]
        if not (0x40 <= e <= len(head) - 24):
            return False
        if head[e:e + 4] != b"PE\x00\x00":
            return False
        # Проверяем наличие сертификата в PE структуре
        # Certificate Table RVA находится в Optional Header в смещении 144 (32-bit) или 160 (64-bit)
        magic = struct.unpack_from("<H", head, e + 24)[0]
        cert_offset = e + 144 if magic == 0x10b else e + 160
        if cert_offset + 8 <= len(head):
            cert_rva, cert_size = struct.unpack_from("<II", head, cert_offset)
            # Если есть сертификат с ненулевым размером — подозрительно
            if cert_rva > 0 and cert_size > 0:
                return True
    except (struct.error, OSError):
        pass
    return False

def pe_header_info(f):

    head = _read_at(f, 0, 0x1000)
    if head[:2] != b"MZ" or len(head) < 0x40:
        return None
    try:
        e = struct.unpack_from("<I", head, 0x3C)[0]
        if not (0x40 <= e <= len(head) - 24):
            return None
        if head[e:e + 4] != b"PE\x00\x00":
            return None
        nsec = struct.unpack_from("<H", head, e + 6)[0]
        opt = struct.unpack_from("<H", head, e + 20)[0]
        magic = struct.unpack_from("<H", head, e + 24)[0]
        if not (0 < nsec <= 96):
            return None

        tbl_off = e + 24 + opt
        tbl = head[tbl_off:tbl_off + 40 * nsec]
        if len(tbl) < 40 * nsec:
            tbl = _read_at(f, tbl_off, 40 * nsec)
        sections, names = [], []
        for i in range(nsec):
            ent = tbl[40 * i:40 * i + 40]
            if len(ent) < 40:
                break
            vs, va, rs, ro = struct.unpack_from("<IIII", ent, 8)
            sections.append((ent[:8], va, vs, ro, rs))
            names.append(ent[:8].rstrip(b"\x00"))

        dd = e + 24 + (112 if magic == 0x20B else 96)

        exp_name = b""
        if len(head) >= dd + 4:
            rva = struct.unpack_from("<I", head, dd)[0]
            if rva:
                o = _rva_to_off(sections, rva)
                if o:
                    ed = _read_at(f, o, 40)
                    if len(ed) >= 16:
                        no = _rva_to_off(sections, struct.unpack_from("<I", ed, 12)[0])
                        if no:
                            exp_name = _read_at(f, no, 64).split(b"\x00")[0]

        pdb = b""
        if len(head) >= dd + 52:
            rva = struct.unpack_from("<I", head, dd + 6 * 8)[0]
            if rva:
                o = _rva_to_off(sections, rva)
                if o:
                    for k in range(4):
                        ent = _read_at(f, o + 28 * k, 28)
                        if len(ent) < 28:
                            break
                        typ, sz, _, ptr = struct.unpack_from("<IIII", ent, 12)
                        if typ == 2 and 24 < sz < 1024:
                            pdb = _read_at(f, ptr + 24, sz - 24).split(b"\x00")[0]
                            break
        return names, exp_name, pdb
    except (struct.error, OSError, ValueError):
        return None

HEADER_TG = "@rustdevchecker"
HEADER_DS = "@alerust"

TRACE_NAMES = [
    "NightWare", "TRPFREE.dll", "cathack", "trace.cc", "266.dll",
    "ardor.dll", "nanohack", "BaffClient", "Superiority", "RustRage",
    "Endless.cc", "settings.xml", "binary.dll", "popkamamont.dll",
    "pasta.dll",
]
INJECTOR_WORDS = ["INJECTOR", "INJECT", "XENOS", "PROCESS HACKER",
                  "CHEAT ENGINE", "CHEATENGINE", "WINJECT", "MANUALMAP"]
EXLOADER = {"rel": "com.swiftsoft/ExLoader/modifications", "ext": ".dat"}

_HINTS = {"names": [], "min_size": MIN_SIZE, "max_size": MAX_SIZE}
_RULES = {"banner": {"tg": HEADER_TG, "ds": HEADER_DS},
          "trace_names": TRACE_NAMES, "injector_words": INJECTOR_WORDS,
          "exloader": EXLOADER}
SCAN_BATCH = 800
HASH_WORKERS = 8

def fetch_hints():
    global _HINTS
    try:
        import urllib.request
        with urllib.request.urlopen(SERVER_URL + "/hints",
                                    timeout=LICENSE_TIMEOUT) as r:
            h = json.loads(r.read().decode("utf-8", "replace"))
        _HINTS = {"names": [str(n).lower() for n in h.get("names", [])],
                  "min_size": int(h.get("min_size", MIN_SIZE)),
                  "max_size": int(h.get("max_size", MAX_SIZE))}
        return True
    except Exception:
        return False

def fingerprint_file(path, size):

    if is_self(path):
        return None
    base = os.path.basename(path)
    try:
        with open(long_path(path), "rb", buffering=0) as f:
            info = pe_header_info(f)
            # Дополнительно проверяем подделку цифровой подписи (признак лоадера)
            fake_sig = _has_fake_signature(f)
    except OSError:
        info = None
        fake_sig = False
    if info is None:

        if _name_hit(base.lower()):
            return {"path": path, "size": size, "basename": base,
                    "sections": [], "export": "", "pdb": "", "fake_sig": fake_sig}
        return None
    names, exp, pdb = info
    return {"path": path, "size": size, "basename": base,
            "sections": [n.decode("latin1", "ignore") for n in names],
            "export": exp.decode("latin1", "ignore"),
            "pdb": pdb.decode("latin1", "ignore"),
            "fake_sig": fake_sig}

def _post_json(url, payload, timeout=30):
    import urllib.request
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))

def _sha256(path):
    try:
        h = hashlib.sha256()
        with open(long_path(path), "rb", buffering=0) as f:
            for chunk in iter(lambda: f.read(CHUNK), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None

def server_scan(fps):
    verdicts, need = {}, []
    for i in range(0, len(fps), SCAN_BATCH):
        r = _post_json(SERVER_URL + "/scan", {"files": fps[i:i + SCAN_BATCH]})
        verdicts.update(r.get("verdicts", {}))
        need += r.get("need_hash", [])
    return verdicts, need

def detect_files(candidates, bar, base, weight):
    total = max(1, len(candidates))
    fps = []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for i, fp in enumerate(pool.map(lambda c: fingerprint_file(*c),
                                        candidates, chunksize=16)):
            if fp:
                fps.append(fp)
            if i % 128 == 0:
                bar.set(base + weight * 0.6 * i / total)
    try:
        verdicts, need = server_scan(fps)
    except Exception:
        return None
    bar.set(base + weight * 0.8)
    need = [p for p in sorted(set(need))
            if not (p in verdicts
                    and any(v["level"] == "exact" for v in verdicts[p]))]
    if need:
        hh = {}
        with ThreadPoolExecutor(max_workers=HASH_WORKERS) as pool:
            for p, d in zip(need, pool.map(_sha256, need)):
                if d:
                    hh[p] = d
        try:
            conf = _post_json(SERVER_URL + "/confirm", {"hashes": hh})
            for p, vs in conf.get("verdicts", {}).items():
                verdicts[p] = vs
        except Exception:
            pass
    bar.set(base + weight)
    sm = {p: s for p, s in candidates}
    out = []
    for p, vs in verdicts.items():
        for v in vs:
            out.append(dict(path=p, size=sm.get(p, 0), cheat=v["cheat"],
                            level=v["level"], reason=v.get("why", "")))
    return out

def _filetime(ft):
    try:
        return time.strftime("%d.%m.%Y %H:%M",
                             time.localtime(ft / 10000000 - 11644473600))
    except (OverflowError, OSError, ValueError):
        return "?"

FSCTL_QUERY_USN_JOURNAL = 0x900F4
FSCTL_READ_USN_JOURNAL = 0x900BB

USN_REASONS = [
    (0x00000100, "создан"),
    (0x00000200, "удалён"),
    (0x00001000, "переименован"),
    (0x00002000, "переименован"),
    (0x00000002, "изменён"),
]

def journal_scan(drives, bar, base, weight):

    if os.name != "nt":
        return [], 0, []

    trace = _RULES["trace_names"]
    pats = [(n, n.lower(), "." in n) for n in trace]
    hits, records = {}, 0
    status = []

    usable = []
    for d in drives:
        fs = fs_name(d)
        if fs != "NTFS":

            status.append((d, f"пропущен: {fs}, журнала не бывает"))
        else:
            usable.append(d)

    for di, root in enumerate(usable):
        vol = root.rstrip("\\")
        share = weight / max(1, len(usable))
        bar.set(base + share * di)

        h = _k32.CreateFileW("\\\\.\\" + vol, 0x80000000, 3, None, 3, 0, None)
        if h in (_INVALID, -1, 0, None):
            status.append((root, "нет доступа к тому (нужен администратор)"))
            continue
        try:
            jd = ctypes.create_string_buffer(80)
            ret = wintypes.DWORD()
            if not _k32.DeviceIoControl(h, FSCTL_QUERY_USN_JOURNAL, None, 0,
                                        jd, 80, ctypes.byref(ret), None):
                err = ctypes.get_last_error()
                status.append((root, "журнал отключён (fsutil usn createjournal)"
                               if err == 1179 else f"журнал недоступен, код {err}"))
                continue
            jid, first, nxt = struct.unpack_from("<Qqq", jd.raw, 0)
            before = records
            span = max(1, nxt - first)

            buf = ctypes.create_string_buffer(1 << 20)
            start = first
            while True:
                inp = ctypes.create_string_buffer(
                    struct.pack("<qIIQQQ", start, 0xFFFFFFFF, 0, 0, 0, jid), 40)
                if not _k32.DeviceIoControl(h, FSCTL_READ_USN_JOURNAL, inp, 40,
                                            buf, ctypes.sizeof(buf),
                                            ctypes.byref(ret), None):
                    break
                if ret.value <= 8:
                    break
                data = buf.raw[:ret.value]
                nextusn = struct.unpack_from("<q", data, 0)[0]
                off = 8
                while off < len(data):
                    rl = struct.unpack_from("<I", data, off)[0]
                    if rl == 0:
                        break
                    fnl, fno = struct.unpack_from("<HH", data, off + 56)
                    name = data[off + fno:off + fno + fnl].decode("utf-16le",
                                                                  "ignore")
                    records += 1
                    low = name.lower()
                    for label, pat, exact in pats:
                        if (low == pat) if exact else (pat in low):
                            frn, par = struct.unpack_from("<QQ", data, off + 8)
                            stamp = struct.unpack_from("<q", data, off + 32)[0]
                            reason = struct.unpack_from("<I", data, off + 40)[0]
                            path = resolve_path(vol, par, name) or (
                                vol + "\\…\\" + name)
                            key = (label, path.lower())
                            rec = hits.get(key)
                            if rec is None:
                                hits[key] = dict(pattern=label, path=path,
                                                 reason=reason, last=stamp)
                            else:
                                rec["reason"] |= reason
                                rec["last"] = max(rec["last"], stamp)
                            break
                    off += rl
                bar.set(base + share * di
                        + share * min(1.0, (start - first) / span))
                if nextusn <= start:
                    break
                start = nextusn
            status.append((root, f"{records - before} записей"))
        finally:
            _k32.CloseHandle(h)

    out = []
    for rec in hits.values():
        acts = []
        for bit, word in USN_REASONS:
            if rec["reason"] & bit and word not in acts:
                acts.append(word)
        out.append(dict(pattern=rec["pattern"], path=rec["path"],
                        when=_filetime(rec["last"]),
                        action=", ".join(acts) or "изменён"))
    out.sort(key=lambda r: (trace.index(r["pattern"]) if r["pattern"] in trace
                            else 999, r["path"].lower()))
    status.sort(key=lambda x: x[0])
    return out, records, status

PREFETCH_DIR = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"),
                            "Prefetch")

INJECTORS = ("INJECT", "XENOS", "PROCESS HACKER", "CHEATENGINE",
             "CHEAT ENGINE", "WINJECT", "MANUALMAP", "GH INJECTOR")
GAMES = ("RUSTCLIENT.EXE", "RUST.EXE")

IGNORE_DLLS = ("WMIS64.DLL",)

SUSPECT_MARKS = ("\\TEMP\\", "\\APPDATA\\", "\\DOWNLOADS\\", "\\DESKTOP\\",
                 "\\RECYCLE", "\\PUBLIC\\", "\\PERFLOGS\\")
SYSTEM_MARKS = ("\\WINDOWS\\", "\\PROGRAM FILES", "\\PROGRAMDATA\\MICROSOFT")

_ntdll = ctypes.WinDLL("ntdll") if os.name == "nt" else None

def _pf_decompress(data):

    if data[:3] != b"MAM":
        return data
    try:
        size = struct.unpack_from("<I", data, 4)[0]
        if not (0 < size <= 64 * 1024 * 1024):
            return None
        out = ctypes.create_string_buffer(size)
        ws = ctypes.c_ulong(0)
        frag = ctypes.c_ulong(0)
        if _ntdll.RtlGetCompressionWorkSpaceSize(ctypes.c_ushort(4),
                                                 ctypes.byref(ws),
                                                 ctypes.byref(frag)) != 0:
            return None
        wsbuf = ctypes.create_string_buffer(ws.value)
        final = ctypes.c_ulong(0)
        if _ntdll.RtlDecompressBufferEx(ctypes.c_ushort(4), out, size,
                                        ctypes.c_char_p(data[8:]),
                                        len(data) - 8, ctypes.byref(final),
                                        wsbuf) != 0:
            return None
        return out.raw[:final.value]
    except (struct.error, OSError, ValueError):
        return None

def volume_map():

    vmap = {}
    if os.name != "nt":
        return vmap
    buf = ctypes.create_unicode_buffer(1024)
    for root in list_drives():
        letter = root.rstrip("\\")
        ser = ctypes.c_ulong(0)
        if ctypes.windll.kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p(root), None, 0, ctypes.byref(ser),
                None, None, None, 0):
            vmap["%08X" % ser.value] = letter
        if ctypes.windll.kernel32.QueryDosDeviceW(ctypes.c_wchar_p(letter),
                                                  buf, 1024):
            dev = buf.value.upper().lstrip("\\")
            if dev.startswith("DEVICE\\"):
                vmap[dev[7:]] = letter
    return vmap

_PF_PATH = None

def pf_normalize(p, vmap):

    up = p.upper().lstrip("\\")
    if up.startswith("VOLUME{"):
        end = up.find("}")
        tail = up[end + 1:] if end > 0 else ""
        serial = up[7:end].split("-")[-1] if end > 0 else ""
        letter = vmap.get(serial.upper())
        return (letter + tail) if letter else ("[том " + serial + "]" + tail)
    if up.startswith("DEVICE\\"):
        rest = up[7:]
        head = rest.split("\\", 1)
        letter = vmap.get(head[0])
        tail = "\\" + head[1] if len(head) > 1 else ""
        return (letter + tail) if letter else p
    return p

def pf_parse(path, vmap):

    try:
        with open(long_path(path), "rb") as f:
            raw = _pf_decompress(f.read())
    except OSError:
        return None
    if not raw or len(raw) < 0x100 or raw[4:8] != b"SCCA":
        return None
    try:
        name = raw[0x10:0x10 + 60].decode("utf-16le", "ignore").split("\x00")[0]
        runs = []
        for v in struct.unpack_from("<8q", raw, 0x80):
            if v <= 0:
                continue
            try:
                t = v / 10000000 - 11644473600
                if 1451606400 < t < 4102444800:
                    runs.append(t)
            except (OverflowError, ValueError):
                pass
        count = struct.unpack_from("<I", raw, 0xC8)[0]
        if count > 100000:
            count = 0
        text = raw.decode("utf-16le", "ignore")
        refs = sorted({pf_normalize(m, vmap)
                       for m in re.findall(r"\\(?:VOLUME|DEVICE)[^\x00]{4,240}",
                                           text)})
        return dict(name=name.upper(), runs=sorted(runs, reverse=True),
                    count=count, refs=refs)
    except (struct.error, UnicodeDecodeError, ValueError):
        return None

def _stamp(ts):
    try:
        return time.strftime("%d.%m.%Y %H:%M", time.localtime(ts))
    except (OSError, OverflowError, ValueError):
        return "?"

ACTIVITY_LAST = 50

def exloader_scan():

    cfg = _RULES.get("exloader") or {}
    rel = os.path.normpath(cfg.get("rel", ""))
    ext = (cfg.get("ext") or ".dat").lower()
    if not rel:
        return []
    bases = set()
    ap = os.environ.get("APPDATA", "")
    if ap:
        bases.add(os.path.join(ap, rel))
    users = os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "Users")
    try:
        for u in os.listdir(users):
            bases.add(os.path.join(users, u, "AppData", "Roaming", rel))
    except OSError:
        pass

    out, seen = [], set()
    for base in sorted(bases):
        if not os.path.isdir(base):
            continue
        try:
            entries = os.listdir(base)
        except OSError:
            continue
        for name in entries:
            if not name.lower().endswith(ext):
                continue
            p = os.path.join(base, name)
            if p.lower() in seen:
                continue
            seen.add(p.lower())
            try:
                st = os.stat(long_path(p))
                out.append((base, name, st.st_size, st.st_mtime))
            except OSError:
                out.append((base, name, 0, 0))
    out.sort(key=lambda r: r[3], reverse=True)
    return out

def activity_scan(bar, base, weight):

    if os.name != "nt" or not os.path.isdir(PREFETCH_DIR):
        return [], []
    try:
        files = [os.path.join(PREFETCH_DIR, f)
                 for f in os.listdir(PREFETCH_DIR) if f.lower().endswith(".pf")]
    except OSError:
        return [], []

    rows = []
    for i, path in enumerate(files):
        if weight:
            bar.set(base + weight * i / max(1, len(files)))
        pf = pf_parse(path, {})
        if not pf:
            continue
        last = pf["runs"][0] if pf["runs"] else 0
        rows.append((last, pf["count"], pf["name"]))

    rows.sort(reverse=True)
    words = _RULES["injector_words"]
    flagged = [r for r in rows if any(k in r[2] for k in words)]
    return rows, flagged

def injection_scan(bar, base, weight):

    out = []
    if os.name != "nt" or not os.path.isdir(PREFETCH_DIR):
        return out, "Prefetch отключён или недоступен"
    try:
        files = [os.path.join(PREFETCH_DIR, f)
                 for f in os.listdir(PREFETCH_DIR) if f.lower().endswith(".pf")]
    except OSError:
        return out, "нет доступа к Prefetch (нужен администратор)"

    vmap = volume_map()
    removable = {d.rstrip("\\") for d in list_drives()
                 if ctypes.windll.kernel32.GetDriveTypeW(
                     ctypes.c_wchar_p(d)) == 2}

    for i, path in enumerate(files):
        bar.set(base + weight * i / max(1, len(files)))
        up = os.path.basename(path).upper()
        is_inj = any(k in up for k in INJECTORS)
        is_game = any(up.startswith(g) for g in GAMES)
        if not (is_inj or is_game):
            continue
        pf = pf_parse(path, vmap)
        if not pf:
            continue

        dlls = [r for r in pf["refs"] if r.upper().endswith(".DLL")
                and not any(r.upper().endswith(w) for w in IGNORE_DLLS)]

        last = pf["runs"][0] if pf["runs"] else 0
        if is_inj:

            picked = [(d, last) for d in dlls
                      if not any(m in d.upper() for m in SYSTEM_MARKS)]
            out.append(dict(kind="injector", name=pf["name"], count=pf["count"],
                            runs=[_stamp(t) for t in pf["runs"]], dlls=picked))
        else:
            game_exe = next((r for r in pf["refs"]
                             if r.upper().endswith(up.split(".EXE")[0] + ".EXE")),
                            "")
            game_dir = game_exe.rsplit("\\", 1)[0].upper() if game_exe else ""
            picked = []
            for d in dlls:
                u = d.upper()
                if any(m in u for m in SYSTEM_MARKS):
                    continue
                if game_dir and u.startswith(game_dir):
                    continue
                if (any(m in u for m in SUSPECT_MARKS)
                        or u[:2] in removable or not game_dir):
                    picked.append((d, last))
            if picked:
                out.append(dict(kind="game", name=pf["name"], count=pf["count"],
                                runs=[_stamp(t) for t in pf["runs"]],
                                dlls=picked))

    merged = {}
    for r in out:
        key = (r["kind"], r["name"])
        cur = merged.get(key)
        if cur is None:
            merged[key] = r
            continue
        cur["count"] += r["count"]
        cur["runs"] = sorted(set(cur["runs"]) | set(r["runs"]), reverse=True)
        cur["dlls"] += r["dlls"]

    for r in merged.values():

        best = {}
        for path, when in r["dlls"]:
            if path not in best or when > best[path]:
                best[path] = when
        r["dlls"] = [{"file": p.rsplit("\\", 1)[-1], "path": p,
                      "when": _stamp(w) if w else "?"}
                     for p, w in sorted(best.items(), key=lambda kv: kv[1],
                                        reverse=True)]

    out = sorted(merged.values(), key=lambda r: (r["kind"] != "injector",
                                                 r["name"]))
    return out, ""

_adv = ctypes.WinDLL("advapi32", use_last_error=True) if os.name == "nt" else None
_HKLM = ctypes.c_void_p(0x80000002)
_KEY_READ = 0x20019
_REG_BACKUP = 0x00000004

DEV_PROPS = {"0064": "установлен", "0065": "первое подключение",
             "0066": "последнее подключение", "0067": "последнее отключение"}
_PROP_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"

def _reg_filetime(path):

    if not _adv:
        return 0
    h = ctypes.c_void_p()
    if _adv.RegOpenKeyExW(_HKLM, path, _REG_BACKUP, _KEY_READ,
                          ctypes.byref(h)) != 0:
        return 0
    buf = ctypes.create_string_buffer(64)
    size = wintypes.DWORD(64)
    typ = wintypes.DWORD()
    st = _adv.RegQueryValueExW(h, None, None, ctypes.byref(typ), buf,
                               ctypes.byref(size))
    _adv.RegCloseKey(h)
    if st != 0 or size.value < 8:
        return 0
    try:
        ft = struct.unpack("<q", buf.raw[:8])[0]
        return ft / 10000000 - 11644473600
    except (struct.error, ValueError, OverflowError):
        return 0

def usb_scan():

    devices = []
    if os.name != "nt":
        return devices, []
    import winreg

    first_seen = {}
    log = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"),
                       "INF", "setupapi.dev.log")
    try:
        with open(log, encoding="utf-8", errors="ignore") as fh:
            txt = fh.read()
        for serial, when in re.findall(
                r"USBSTOR#Disk[^#\n]*#([^#\n]+)#[^\n]*\n>>>\s+Section start "
                r"([0-9/]+ [0-9:.]+)", txt):
            key = serial.split("&")[0].upper()
            first_seen.setdefault(key, when.strip())
    except OSError:
        pass

    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                              r"SYSTEM\CurrentControlSet\Enum\USBSTOR")
    except OSError:
        return devices, []

    i = 0
    while True:
        try:
            model = winreg.EnumKey(root, i)
        except OSError:
            break
        i += 1
        try:
            mk = winreg.OpenKey(root, model)
        except OSError:
            continue
        j = 0
        while True:
            try:
                inst = winreg.EnumKey(mk, j)
            except OSError:
                break
            j += 1
            try:
                ik = winreg.OpenKey(mk, inst)
                friendly = winreg.QueryValueEx(ik, "FriendlyName")[0]
            except OSError:
                friendly = model.replace("Disk&Ven_", "").replace("&Rev_", " ")
            serial = inst.split("&")[0]
            devpath = ("SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\"
                       + model + "\\" + inst + "\\Properties\\" + _PROP_GUID)
            times = {}
            for code, label in DEV_PROPS.items():
                val = _reg_filetime(devpath + "\\" + code)
                if val:
                    times[label] = val
            on = times.get("последнее подключение", 0)
            off = times.get("последнее отключение", 0)
            devices.append(dict(
                name=friendly, serial=serial,
                first=_stamp(times["первое подключение"])
                if times.get("первое подключение")
                else first_seen.get(serial.upper(), ""),
                last_on=_stamp(on) if on else "",
                last_off=_stamp(off) if off else "",
                last_on_ts=on, last_off_ts=off))

    now = []
    for d in list_drives():
        letter = d.rstrip("\\")
        if ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(d)) != 2:
            continue
        label = ctypes.create_unicode_buffer(64)
        fs = ctypes.create_unicode_buffer(16)
        ser = ctypes.c_ulong(0)
        ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(d), label, 64, ctypes.byref(ser), None, None, fs, 16)
        now.append(dict(letter=letter, label=label.value, fs=fs.value,
                        serial="%08X" % ser.value))
    devices.sort(key=lambda x: x["name"].lower())
    return devices, now

class _MOD(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_ulong), ("th32ModuleID", ctypes.c_ulong),
                ("th32ProcessID", ctypes.c_ulong), ("GlblcntUsage", ctypes.c_ulong),
                ("ProccntUsage", ctypes.c_ulong), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", ctypes.c_ulong), ("hModule", ctypes.c_void_p),
                ("szModule", ctypes.c_wchar * 256), ("szExePath", ctypes.c_wchar * 260)]

class _PROC(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
                ("th32ProcessID", ctypes.c_ulong), ("th32DefaultHeapID", ctypes.c_void_p),
                ("th32ModuleID", ctypes.c_ulong), ("cntThreads", ctypes.c_ulong),
                ("th32ParentProcessID", ctypes.c_ulong), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", ctypes.c_ulong), ("szExeFile", ctypes.c_wchar * 260)]

def module_candidates(bar, base, weight):

    if os.name != "nt":
        return []
    k32 = ctypes.windll.kernel32
    out, checked = [], set()

    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    if snap in (-1, 0):
        return []
    pe = _PROC()
    pe.dwSize = ctypes.sizeof(pe)
    procs = []
    if k32.Process32FirstW(snap, ctypes.byref(pe)):
        while True:
            procs.append(pe.th32ProcessID)
            if not k32.Process32NextW(snap, ctypes.byref(pe)):
                break
    k32.CloseHandle(snap)

    for i, pid in enumerate(procs):
        bar.set(base + weight * i / max(1, len(procs)))
        ms = k32.CreateToolhelp32Snapshot(0x8 | 0x10, pid)
        if ms in (-1, 0):
            continue
        me = _MOD()
        me.dwSize = ctypes.sizeof(me)
        if k32.Module32FirstW(ms, ctypes.byref(me)):
            while True:
                path = me.szExePath
                if path and path.lower() not in checked:
                    checked.add(path.lower())
                    try:
                        sz = os.path.getsize(long_path(path))
                    except OSError:
                        sz = me.modBaseSize
                    out.append((path, sz))
                if not k32.Module32NextW(ms, ctypes.byref(me)):
                    break
        k32.CloseHandle(ms)
    return out

ORDER = {"exact": 0, "header": 1, "strong": 2, "weak": 3, "name": 4}

SERVER_URL = "http://93.152.223.197:8090"
LICENSE_TIMEOUT = 4
DISABLED_TEXT = "чекер выключен. владелец Discord: @alerust"

def license_check():

    try:
        import urllib.request
        req = urllib.request.Request(SERVER_URL + "/status",
                                     headers={"User-Agent": "checker"})
        with urllib.request.urlopen(req, timeout=LICENSE_TIMEOUT) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return True, ""
    if data.get("enabled", True):
        return True, ""
    return False, str(data.get("message") or DISABLED_TEXT)

HIST_KEYWORDS = [
    "rust cheat", "rust hack", "rust cheats", "rust hacks",
    "раст чит", "раст читы", "rust aimbot", "rust esp", "rust wallhack",
    "rust script", "rust no recoil", "rust norecoil", "rust silent aim",
    "rust triggerbot", "чит на раст", "читы на раст",
    "macros", "macro", "макрос", "макросы", "no recoil macro",
    "recoil macro", "макрос отдачи", "макрос на раст", "rust macro",
    "logitech macro", "lgs macro", "ghub macro", "bloody macro",
    "razer macro", "oscar editor", "mouse macro",
    "spoofer", "spoofer hwid", "hwid spoofer", "hwid spoof", "спуфер",
    "спуфер hwid", "раст спуфер", "rust spoofer", "serial spoofer",
    "disk spoofer", "mac spoofer", "temp spoofer", "permanent spoofer",
    "clean hwid", "unban rust",
    "dlc rust", "rust dlc", "раст dlc", "раст длс", "длс раст", "длс на раст",
    "dlc чит", "чит dlc", "free dlc", "rust free dlc", "rust dlc free",
    "бесплатные dlc", "бесплатный dlc", "dlc бесплатно", "длс бесплатно",
    "rust skins free", "free skins rust", "rust free skins",
    "dlc unlocker", "dlc анлокер", "rust dlc unlocker",
    "unknowncheats", "elitepvpers", "yougame", "zascriptt", "skidproof",
    "rustcheatz", "edge cheat", "xone cheat",
    "ardor", "powerhack", "superiority", "nanohack", "suckmaster",
    "catcheat", "rustrage", "nightware", "mivison", "exloader", "swiftsoft",
]
HIST_KEYWORDS = sorted(set(k.lower() for k in HIST_KEYWORDS),
                       key=len, reverse=True)

HIST_CAT = {
    "cheat":   ("Чит / Cheat",      RED),
    "spoofer": ("Спуфер / Spoofer", RED),
    "macro":   ("Макрос / Macro",   YEL),
    "dlc":     ("DLC / Скины",      YEL),
}
HIST_ORDER = ["cheat", "spoofer", "macro", "dlc"]


def _hist_profiles(base):
    out = []
    if not base or not os.path.isdir(base):
        return out
    try:
        for name in os.listdir(base):
            if name == "Default" or name.startswith("Profile"):
                h = os.path.join(base, name, "History")
                if os.path.isfile(h):
                    out.append(h)
    except OSError:
        pass
    return out


def _hist_sources():
    local = os.environ.get("LOCALAPPDATA", "")
    roam = os.environ.get("APPDATA", "")
    src = []

    chromium = [
        os.path.join(local, "Google", "Chrome", "User Data"),
        os.path.join(local, "Google", "Chrome Beta", "User Data"),
        os.path.join(local, "Microsoft", "Edge", "User Data"),
        os.path.join(local, "Microsoft", "Edge Beta", "User Data"),
        os.path.join(local, "Microsoft", "Edge Dev", "User Data"),
        os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data"),
        os.path.join(local, "Vivaldi", "User Data"),
        os.path.join(local, "Chromium", "User Data"),
        os.path.join(local, "Yandex", "YandexBrowser", "User Data"),
        os.path.join(roam, "Opera Software", "Opera Stable"),
        os.path.join(roam, "Opera Software", "Opera GX Stable"),
        os.path.join(roam, "Opera Software", "Opera Crypto Stable"),
        os.path.join(local, "Amigo", "User Data"),
        os.path.join(local, "Mail.Ru", "Atom", "User Data"),
        os.path.join(local, "CocCoc", "Browser", "User Data"),
    ]
    for base in chromium:
        direct = os.path.join(base, "History")
        if os.path.isfile(direct):
            src.append(("chromium", direct))
        for path in _hist_profiles(base):
            src.append(("chromium", path))

    firefox = [
        os.path.join(roam, "Mozilla", "Firefox", "Profiles"),
        os.path.join(roam, "Waterfox", "Profiles"),
        os.path.join(roam, "librewolf", "Profiles"),
    ]
    for base in firefox:
        if not base or not os.path.isdir(base):
            continue
        try:
            for prof in os.listdir(base):
                path = os.path.join(base, prof, "places.sqlite")
                if os.path.isfile(path):
                    src.append(("firefox", path))
        except OSError:
            pass
    return src


def _hist_copy(path):
    tmpdir = tempfile.mkdtemp(prefix="h_")
    dst = os.path.join(tmpdir, "db")
    try:
        shutil.copy2(path, dst)
        for ext in ("-wal", "-shm"):
            if os.path.isfile(path + ext):
                shutil.copy2(path + ext, dst + ext)
        return tmpdir, dst
    except OSError:
        return tmpdir, None


def _read_hist(kind, dbpath):
    tmpdir, dst = _hist_copy(dbpath)
    rows = []
    try:
        if not dst:
            return rows
        con = sqlite3.connect(f"file:{dst}?mode=ro", uri=True, timeout=5)
        con.text_factory = lambda b: b.decode("utf-8", "replace")
        cur = con.cursor()
        if kind == "chromium":
            cur.execute("SELECT url, title FROM urls")
        else:
            cur.execute("SELECT url, title FROM moz_places")
        for url, title in cur.fetchall():
            rows.append((url or "", title or ""))
        con.close()
    except sqlite3.Error:
        pass
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return rows


def _dom(url):
    try:
        net = urlparse(url).netloc.lower()
    except ValueError:
        return ""
    if net.startswith("www."):
        net = net[4:]
    return net.split(":")[0]


def _hist_match(url, title):
    hay = (url + " " + title + " " + unquote(url)).lower()
    return [k for k in HIST_KEYWORDS if k in hay]


def history_collect():
    doms = {}
    for kind, path in _hist_sources():
        for url, title in _read_hist(kind, path):
            found = _hist_match(url, title)
            if not found:
                continue
            d = _dom(url) or "(без домена)"
            box = doms.setdefault(d, {"urls": set(), "title": "", "kw": set()})
            box["urls"].add(url)
            if not box["title"] and title:
                box["title"] = title
            box["kw"].update(found)
    return doms


def history_send(doms):
    import urllib.request
    payload = {"domains": []}
    for d, box in list(doms.items())[:150]:
        payload["domains"].append({"domain": d, "title": box["title"][:80],
                                    "kw": sorted(box["kw"])[:6]})
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(SERVER_URL + "/history", data=body,
                                 method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        return data.get("verdict"), data.get("checks")
    except Exception:
        return None, None

def print_header():
    if os.name == "nt":
        try:
            ctypes.windll.kernel32.SetConsoleTitleW(
                f"TG {HEADER_TG}   DS {HEADER_DS}")
        except Exception:
            pass
    print()
    print(f"  {CYN}TG:  {HEADER_TG}{R}")
    print(f"  {CYN}DS:  {HEADER_DS}{R}")
    print()

def main():
    quiet = "--quiet" in sys.argv
    fast = "--fast" in sys.argv
    deep = "--deep" in sys.argv
    want_json = "--json" in sys.argv

    print_header()
    allowed, msg = license_check()
    if not allowed:
        print()
        print(f"  {RED}[*] {msg}{R}")
        print()
        return 3

    server_ok = fetch_hints()
    roots = hot_roots() if fast else list_drives()

    print()
    t0 = time.time()

    # ==== АСИНХРОННЫЙ запуск: memory scan работает параллельно ====
    try:
        # onefile: memory_scan.py лежит в _MEIPASS
        _mei = getattr(sys, "_MEIPASS", None)
        if _mei and _mei not in sys.path:
            sys.path.insert(0, _mei)
        import memory_scan
        mem_bar_shadow = Progress("Проверка памяти RustClient.exe", enabled=False)
        mem_result = {"status": None, "findings": None}
        def _mem_worker():
            # даём файловому сканеру стартовать первым, чтобы он не ждал GIL
            time.sleep(0.3)
            try:
                st, f = memory_scan.scan(mem_bar_shadow, 0.0, 1.0)
                mem_result["status"] = st
                mem_result["findings"] = f
            except Exception:
                mem_result["status"] = "error"
                mem_result["findings"] = []
        mem_thread = threading.Thread(target=_mem_worker, daemon=True)
        mem_thread.start()
    except Exception:
        mem_thread = None
        mem_result = {"status": "error", "findings": []}

    bar = Progress("Поиск файлов", enabled=not quiet).start()
    findings, scanned = [], 0
    if server_ok:
        stats = Stats()
        mods = module_candidates(bar, 0.0, 0.05)
        cands = collect(roots, deep, stats, bar, 0.05, 0.45)
        allc = list(dict.fromkeys(cands + mods))
        scanned = len(allc)
        res = detect_files(allc, bar, 0.5, 0.5)
        if res is None:
            server_ok = False
        else:
            findings = res
    bar.set(1.0)
    bar.stop()

    uniq = {}
    for f in findings:
        k = (f["path"].lower(), f["cheat"])
        if k not in uniq or ORDER[f["level"]] < ORDER[uniq[k]["level"]]:
            uniq[k] = f
    findings = sorted(uniq.values(), key=lambda x: (ORDER[x["level"]], x["cheat"]))
    dt = time.time() - t0
    hard = [f for f in findings if f["level"] != "name"]
    hits = sorted({f["cheat"] for f in hard})
    cheats = sorted({f["cheat"] for f in findings})

    print()
    if not server_ok:
        print(f"  {YEL}[*] Проверка файлов недоступна: сервер не отвечает{R}")
        print()
    elif hits:
        print(f"  {RED}[*] Найден {', '.join(hits)}{R}")
        print()
    else:
        print(f"  {GRN}[*] Ничего не найдено{R}")
        print()
    for c in cheats:
        mine = [f for f in findings if f["cheat"] == c]
        col = RED if any(f["level"] != "name" for f in mine) else YEL
        print(f"  {col}[*] {c}{R}")
        for f in mine:
            tail = f"  {GRY}(только по имени){R}" if f["level"] == "name" else ""
            print(f"      {f['path']}{tail}")
        print()
    print(f"  {GRY}{scanned} файлов, {dt:.1f} c{R}")
    print()

    # ==== ВЫВОД MEMORY SCAN (memory работал в параллель) ====
    tm0 = time.time()
    mbar = Progress("Сканирование памяти RustClient.exe", enabled=not quiet).start()
    if mem_thread is not None:
        while mem_thread.is_alive():
            try:
                mbar.set(mem_bar_shadow.frac)
            except Exception:
                pass
            time.sleep(0.1)
        mem_thread.join(timeout=1)
    mbar.set(1.0)
    mbar.stop()

    mstat = mem_result.get("status") or "error"
    mfind = mem_result.get("findings") or []
    mdt = time.time() - tm0
    print()
    if mstat == "no_process":
        print(f"  {GRY}[*] Память RustClient.exe — процесс не запущен{R}")
    elif mstat == "no_access":
        print(f"  {YEL}[*] Память RustClient.exe — нет доступа (нужен админ){R}")
    elif mstat == "error":
        print(f"  {YEL}[*] Память RustClient.exe — ошибка сканирования{R}")
    elif mfind:
        print(f"  {RED}[*] Подозрительные DLL в памяти — {len(mfind)}{R}")
        for d in mfind[:30]:
            print(f"      {d}")
        if len(mfind) > 30:
            print(f"      {GRY}... и ещё {len(mfind) - 30}{R}")
    else:
        print(f"  {GRN}[*] Память RustClient.exe — подозрительных DLL нет{R}")
    print(f"  {GRY}{mdt:.1f} c{R}")
    print()

    t1 = time.time()
    jbar = Progress("JournalTrace поиск", enabled=not quiet).start()
    traces, records, jstatus = journal_scan(list_drives(), jbar, 0.0, 1.0)
    jbar.set(1.0)
    jbar.stop()
    jdt = time.time() - t1
    pats = []
    for t in traces:
        if t["pattern"] not in pats:
            pats.append(t["pattern"])
    print()
    if pats:
        print(f"  {RED}[*] JournalTrace — найден {', '.join(pats)}{R}")
    else:
        print(f"  {GRN}[*] JournalTrace — ничего не найдено{R}")
    print()
    for n in pats:
        print(f"  {RED}[*] {n}{R}")
        for t in traces:
            if t["pattern"] == n:
                print(f"      {t['path']}   {GRY}{t['action']}, {t['when']}{R}")
        print()
    for drive, note in jstatus:
        print(f"  {GRY}{drive:<4} {note}{R}")
    print(f"  {GRY}всего {records} записей, {jdt:.1f} c{R}")
    print()

    t2 = time.time()
    ibar = Progress("Следы инжекта", enabled=not quiet).start()
    inj, ierr = injection_scan(ibar, 0.0, 1.0)
    ibar.set(1.0)
    ibar.stop()
    print()
    if ierr:
        print(f"  {YEL}[*] Следы инжекта — {ierr}{R}")
    elif inj:
        print(f"  {RED}[*] Найдены следы инжекта{R}")
    else:
        print(f"  {GRN}[*] Следов инжекта не найдено{R}")
    print()
    for r in inj:
        last = r["runs"][0] if r["runs"] else "?"
        head = "инжектор" if r["kind"] == "injector" else "игра грузила чужую DLL"
        print(f"  {RED}[*] {r['name']}{R}   {GRY}{head}, запусков "
              f"{r['count']}, последний {last}{R}")
        for d in r["dlls"]:
            print(f"      {d['file']:<34} {GRY}{d['when']}{R}")
        print()
    print(f"  {GRY}{time.time() - t2:.1f} c{R}")
    print()

    devices, plugged = usb_scan()
    ua = is_admin()
    if devices:
        print(f"  {CYN}[*] USB-накопители — {len(devices)} за всю историю{R}")
        if not ua:
            print(f"      {YEL}времена недоступны без прав администратора{R}")
        print()
        for d in devices:
            print(f"      {d['name']}")
            print(f"      {GRY}серийный {d['serial']}{R}")
            if ua:
                print(f"      {GRY}последнее отключение: "
                      f"{d['last_off'] or 'нет записи'}{R}")
            print()
    rec = sorted((d for d in devices
                  if d["last_off_ts"] > 0 and d["last_off_ts"] > time.time() - USB_RECENT_HOURS * 3600),
                 key=lambda d: d["last_off_ts"], reverse=True)
    print(f"  {YEL}[*] Отключённые недавно{R}   {GRY}за {USB_RECENT_HOURS} часа{R}")
    print()
    if not ua:
        print(f"      {GRY}недоступно без прав администратора{R}")
        print()
    elif not rec:
        print(f"      {GRY}нет{R}")
        print()
    for d in rec:
        print(f"      {d['name']}")
        print(f"      {GRY}серийный {d['serial']}{R}")
        print(f"      {GRY}отключён: {d['last_off']}{R}")
        print()
    if plugged:
        print(f"  {YEL}[*] Подключены сейчас{R}")
        print()
        for d in plugged:
            print(f"      {d['letter']}  {d['label'] or 'без метки'} "
                  f"{GRY}({d['fs']}, серийный тома {d['serial']}){R}")
        print()

    exl = exloader_scan()
    print()
    if exl:
        print(f"  {RED}[*] ExLoader — найдено {len(exl)} .dat{R}")
        print()
        cur = None
        for base, name, sz, mt in exl:
            if base != cur:
                cur = base
                print(f"      {GRY}{base}{R}")
            print(f"      {RED}{name}{R}   {GRY}{human(sz)}, "
                  f"{_stamp(mt) if mt else '—'}{R}")
        print()
    else:
        print(f"  {GRN}[*] ExLoader — не найдено{R}")
        print()

    abar = Progress("Последняя активность", enabled=not quiet).start()
    activity, injectors = activity_scan(abar, 0.0, 1.0)
    abar.set(1.0)
    abar.stop()
    print()
    if not ua:
        print(f"  {YEL}[*] Последняя активность — недоступно без прав администратора{R}")
        print()
    elif not activity:
        print(f"  {GRN}[*] Последняя активность — Prefetch пуст или отключён{R}")
        print()
    else:
        if injectors:
            print(f"  {RED}[*] Обнаружены инжекторы (по слову INJECTOR){R}")
            print()
            for last, count, name in injectors:
                print(f"      {RED}{name}{R}   {GRY}запусков {count}, "
                      f"последний {_stamp(last) if last else '—'}{R}")
            print()
        else:
            print(f"  {GRN}[*] Инжекторов в активности не найдено{R}")
            print()
        print(f"  {CYN}[*] Последние {min(ACTIVITY_LAST, len(activity))} запусков{R}")
        print()
        for last, count, name in activity[:ACTIVITY_LAST]:
            mark = f"  {RED}<< инжектор{R}" if any(
                k in name for k in INJECTOR_WORDS) else ""
            print(f"      {GRY}{_stamp(last) if last else '—':<16}{R} {name}{mark}")
        print()

    hbar = Progress("История браузеров", enabled=not quiet).start()
    doms = history_collect()
    hbar.set(1.0)
    hbar.stop()
    verdict, checks = history_send(doms)
    print()
    buckets = {c: [] for c in HIST_ORDER}
    for d, box in doms.items():
        cat = (verdict or {}).get(d, "cheat")
        if cat in buckets:
            buckets[cat].append(box)
    danger = any(buckets[c] for c in HIST_ORDER)
    if verdict is None and doms:
        print(f"  {YEL}[*] История браузеров — сервер не ответил, "
              f"показываю все совпадения{R}")
        print()
    if danger:
        print(f"  {RED}[*] История браузеров — найдены следы "
              f"читов/спуферов/макросов{R}")
    else:
        print(f"  {GRN}[*] История браузеров — подозрительного не найдено{R}")
    print()
    for cat in HIST_ORDER:
        items = buckets[cat]
        if not items:
            continue
        label, col = HIST_CAT[cat]
        links = []
        for box in items:
            links.extend(sorted(box["urls"]))
        n = len(links)
        word = "ссылка" if n % 10 == 1 and n % 100 != 11 else (
            "ссылки" if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14
            else "ссылок")
        shown = links[:40]
        more = n - len(shown)
        tail = f"  {GRY}… и ещё {more}{R}" if more > 0 else ""
        print(f"  {col}[*] {label}{R}  {GRY}({n} {word}){R}")
        print(f"      {', '.join(shown)}{tail}")
        print()

    if want_json:
        out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "result.json")
        try:
            with open(out, "w", encoding="utf-8") as fh:
                json.dump({"found": hits, "findings": findings,
                           "journal": traces, "injection": inj,
                           "usb": devices, "exloader": exl}, fh,
                          ensure_ascii=False, indent=2, default=str)
        except OSError:
            pass
    return 1 if (hard or traces or inj or injectors or exl or danger) else 0

def _run():
    code = main()

    if sys.stdout.isatty() and "--nopause" not in sys.argv:
        try:
            input("\n  Нажми Enter, чтобы закрыть...")
        except (EOFError, KeyboardInterrupt):
            pass
    return code

if __name__ == "__main__":

    import multiprocessing
    multiprocessing.freeze_support()
    try:
        sys.exit(_run())
    except KeyboardInterrupt:
        print("\nПрервано.")
        sys.exit(2)
