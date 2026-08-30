# -*- coding: utf-8 -*-
"""
Memory scan модуль для checker.py.
Сканирует память RustClient.exe в поисках подозрительных .dll путей.
Используется асинхронно параллельно с файловым сканированием.
"""

import ctypes
from ctypes import wintypes
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================
# Windows API
# ============================================================

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000

PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

TH32CS_SNAPPROCESS = 0x00000002

MEM_THREADS = 4          # мало потоков чтобы не мешать файловому сканеру
MAX_REGION_SIZE = 100 * 1024 * 1024
MIN_REGION_SIZE = 4096   # игнор мелких регионов (тратим на них только оверхед)
MIN_PATH_LEN = 8
MAX_PATH_LEN = 260

DLL_ASCII = b'.dll'
DLL_UNICODE = b'.\x00d\x00l\x00l\x00'

TARGET_PROCESS = "RustClient.exe"


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_char * 260),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


# ВАЖНО: отдельный WinDLL инстанс, чтобы наши argtypes/restype не ломали
# глобальный ctypes.windll.kernel32, используемый другими модулями (checker.py).
_k32 = ctypes.WinDLL('kernel32', use_last_error=True)
_k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_k32.OpenProcess.restype = wintypes.HANDLE
_k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                  ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
_k32.VirtualQueryEx.restype = ctypes.c_size_t
_k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
_k32.ReadProcessMemory.restype = wintypes.BOOL
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.CloseHandle.restype = wintypes.BOOL
_k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
_k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
_k32.Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
_k32.Process32First.restype = wintypes.BOOL
_k32.Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
_k32.Process32Next.restype = wintypes.BOOL


# ============================================================
# Фильтры системных / игровых DLL
# ============================================================

SYSTEM_PATHS = [
    "c:/windows/", "c:/program files/", "c:/program files (x86)/",
    "/system32/", "/syswow64/", "/windowsapps/", "/microsoft/",
    "/programdata/microsoft", "/nvidia corporation/",
    "/rustclient_data/", "/companyrust/", "/rust/",
    "/managed/", "/plugins/", "/steam/steamapps/common/",
]

SYSTEM_PREFIXES = [
    "unityengine.", "unity.", "facepunch.", "system.", "microsoft.",
    "api-ms-win-", "ext-ms-win-", "wpf.", "presentationframework.",
]

SYSTEM_DLLS = {
    "kernel32.dll", "kernelbase.dll", "kernel.appcore.dll", "ntdll.dll",
    "user32.dll", "gdi32.dll", "gdi32full.dll", "advapi32.dll",
    "msvcrt.dll", "ole32.dll", "oleaut32.dll", "shell32.dll", "shlwapi.dll",
    "shcore.dll", "ws2_32.dll", "wininet.dll", "winhttp.dll", "webio.dll",
    "crypt32.dll", "cryptsp.dll", "cryptdll.dll", "cryptbase.dll",
    "bcrypt.dll", "bcryptprimitives.dll", "rpcrt4.dll", "sechost.dll",
    "combase.dll", "clbcatq.dll", "sspicli.dll", "secur32.dll",
    "wldp.dll", "profapi.dll", "psapi.dll", "version.dll", "imm32.dll",
    "gdiplus.dll", "comctl32.dll", "comdlg32.dll", "setupapi.dll",
    "iphlpapi.dll", "dnsapi.dll", "netapi32.dll", "mswsock.dll",
    "userenv.dll", "propsys.dll", "wtsapi32.dll", "powrprof.dll",
    "winmm.dll", "avrt.dll", "audioses.dll", "mmdevapi.dll",
    "ucrtbase.dll", "urlmon.dll", "msi.dll", "wintrust.dll",
    "windowscodecs.dll", "windows.storage.dll", "windows.ui.dll",
    "coreuicomponents.dll", "coremessaging.dll", "textinputframework.dll",
    "twinapi.dll", "wintypes.dll", "dcomp.dll", "dbghelp.dll",
    "dbgcore.dll", "symsrv.dll", "msvcp_win.dll", "msvcp140.dll",
    "msvcp140_1.dll", "msvcp140_2.dll", "vcruntime140.dll",
    "vcruntime140_1.dll", "vccorlib140.dll", "concrt140.dll",
    "concrt140_1.dll", "gpupdate.dll", "srvcli.dll", "netutils.dll",
    "logoncli.dll", "samcli.dll", "wkscli.dll", "browcli.dll",
    "napinsp.dll", "nlansp_c.dll", "nlasvc.dll", "pnrpnsp.dll",
    "rasadhlp.dll", "winrnr.dll", "wshbth.dll", "wshqos.dll",
    "wshtcpip.dll", "resourcepolicyclient.dll", "tzres.dll",
    "imageres.dll", "uxtheme.dll", "dwmapi.dll",
    "d3d11.dll", "d3d12.dll", "d3d9.dll", "d3d.dll", "ddraw.dll",
    "dxgi.dll", "opengl32.dll", "d3dcompiler_47.dll", "d3dcompiler.dll",
    "d3dscache.dll", "vulkan-1.dll", "vk_swiftshader.dll", "vkd3d.dll",
    "xinput1_3.dll", "xinput9_1_0.dll", "xaudio2_7.dll", "xaudio2_9.dll",
    "openal32.dll", "libcurl.dll",
    "fx_dx12.dll", "x_dx12.dll", "lityfx_dx12.dll", "lityfx_vk.dll",
    "layrenderer64.dll", "engl32.dll",
    "nvcuda.dll", "nvfatbinaryloader.dll", "nvapi64.dll", "nvapi.dll",
    "nvcuvid.dll", "nvencodeapi64.dll", "nvldumd.dll", "nvldumdx.dll",
    "nvppex.dll", "nvmessagebus.dll",
    "amdxx64.dll", "amdihk64.dll", "atiadlxx.dll", "atiadlxy.dll",
    "mf.dll", "mferror.dll", "mfreadwrite.dll", "msrawimage.dll",
    "steam_api64.dll", "steam_api.dll", "steamclient.dll",
    "steamclient64.dll", "gameoverlayrenderer.dll",
    "gameoverlayrenderer64.dll", "eac_launcher.dll",
    "easyanticheat_x64.dll", "easyanticheat.dll",
    "eossdk-win64-shipping.dll", "k-win64-shipping.dll", "tier0_s64.dll",
    "unityplayer.dll", "mono-2.0-bdwgc.dll", "mono.dll",
    "assembly-csharp.dll", "assembly-csharp-firstpass.dll",
    "gameassembly.dll", "baselib.dll", "raknet.dll", "rustnative.dll",
    "sqlite3.dll", "mscorlib.dll",
    "gfxplugindlssnative.dll", "gfxpluginnvidiareflex.dll",
    "melanchall.drywetmidi.dll", "chrome_elf.dll",
    "ore-delayload-l1-1-0.dll", "redist.dll", "wmis64.dll",
}


def _is_system_dll(dll_path):
    p = dll_path.lower().replace("\\", "/")
    for sp in SYSTEM_PATHS:
        if sp in p:
            return True
    name = p.rsplit("/", 1)[-1]
    for pref in SYSTEM_PREFIXES:
        if name.startswith(pref):
            return True
    if name in SYSTEM_DLLS:
        return True
    if name.startswith("api-ms-") or name.startswith("ext-ms-"):
        return True
    return False


def _clean_dll_name(raw):
    s = raw.strip()
    if not s.lower().endswith('.dll'):
        return None
    fname = s.replace('\\', '/').rsplit('/', 1)[-1]
    if fname.endswith(':') or len(fname) < MIN_PATH_LEN:
        return None
    if not fname[0].isalpha() and fname[0] != '_':
        return None
    base = fname[:-4]
    if len(base) < 4:
        return None
    for c in fname:
        if not (c.isalnum() or c in '.-_ '):
            return None
    return s


def _find_dlls(data):
    out = set()

    pos = 0
    while True:
        idx = data.find(DLL_ASCII, pos)
        if idx == -1:
            break
        start = idx
        while start > 0 and (idx - start) < MAX_PATH_LEN:
            b = data[start - 1]
            if b == 0 or b < 0x20 or b > 0x7E:
                break
            start -= 1
        end = idx + 4
        if end - start >= MIN_PATH_LEN:
            try:
                cleaned = _clean_dll_name(data[start:end].decode('ascii', errors='ignore'))
                if cleaned:
                    out.add(cleaned)
            except Exception:
                pass
        pos = idx + 4

    pos = 0
    while True:
        idx = data.find(DLL_UNICODE, pos)
        if idx == -1:
            break
        start = idx
        while start >= 2 and (idx - start) < MAX_PATH_LEN * 2:
            b1 = data[start - 2]
            b2 = data[start - 1]
            if b2 != 0 or b1 == 0 or b1 < 0x20 or b1 > 0x7E:
                break
            start -= 2
        end = idx + 8
        if end - start >= MIN_PATH_LEN * 2:
            try:
                cleaned = _clean_dll_name(data[start:end].decode('utf-16-le', errors='ignore'))
                if cleaned:
                    out.add(cleaned)
            except Exception:
                pass
        pos = idx + 8

    return out


def _is_zero(data):
    if len(data) < 8192:
        return data.count(b'\x00') == len(data)
    return (data[:4096].count(b'\x00') == 4096 and
            data[-4096:].count(b'\x00') == 4096)


def _find_process(name):
    snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return None
    e = PROCESSENTRY32()
    e.dwSize = ctypes.sizeof(PROCESSENTRY32)
    pid = None
    if _k32.Process32First(snap, ctypes.byref(e)):
        while True:
            n = e.szExeFile.decode('utf-8', errors='ignore')
            if n.lower() == name.lower():
                pid = e.th32ProcessID
                break
            if not _k32.Process32Next(snap, ctypes.byref(e)):
                break
    _k32.CloseHandle(snap)
    return pid


def _regions(handle):
    out = []
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    while addr < 0x7FFFFFFFFFFF:
        r = _k32.VirtualQueryEx(handle, ctypes.c_void_p(addr),
                                 ctypes.byref(mbi), ctypes.sizeof(mbi))
        if r == 0:
            break
        if (mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE and
            mbi.Protect not in (PAGE_NOACCESS, 0) and
            not (mbi.Protect & PAGE_GUARD)):
            if MIN_REGION_SIZE <= mbi.RegionSize <= MAX_REGION_SIZE:
                out.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = (mbi.BaseAddress or 0) + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return out


def _scan_region(handle, base, size):
    try:
        buf = (ctypes.c_ubyte * size)()
        br = ctypes.c_size_t(0)
        if not _k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size, ctypes.byref(br)):
            return set()
        n = br.value
        if n == 0:
            return set()
        # string_at делает bytes без Python-цикла копирования - в разы быстрее
        data = ctypes.string_at(ctypes.addressof(buf), n)
        # быстрая проверка: пустая ли страница
        if _is_zero(data):
            return set()
        # быстрая проверка: есть ли вообще .dll
        if data.find(DLL_ASCII) == -1 and data.find(DLL_UNICODE) == -1:
            return set()
        return _find_dlls(data)
    except Exception:
        return set()


# ============================================================
# ПУБЛИЧНЫЙ API
# ============================================================

def scan(bar=None, frac_from=0.0, frac_to=1.0):
    """
    Сканирует память RustClient.exe.
    bar - объект Progress (опционально)
    Возвращает: (status, findings)
      status: "ok" | "no_process" | "no_access" | "error"
      findings: list[str] - подозрительные .dll (не системные)
    """
    pid = _find_process(TARGET_PROCESS)
    if not pid:
        if bar:
            bar.set(frac_to)
        return ("no_process", [])

    handle = _k32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False, pid
    )
    if not handle:
        if bar:
            bar.set(frac_to)
        return ("no_access", [])

    try:
        regs = _regions(handle)
        total = len(regs)
        if total == 0:
            if bar:
                bar.set(frac_to)
            return ("ok", [])

        done = [0]
        span = frac_to - frac_from
        all_dlls = set()

        def _update():
            if bar:
                bar.set(frac_from + span * (done[0] / total))

        with ThreadPoolExecutor(max_workers=MEM_THREADS) as ex:
            futs = [ex.submit(_scan_region, handle, b, s) for b, s in regs]
            for f in as_completed(futs):
                r = f.result()
                if r:
                    all_dlls.update(r)
                done[0] += 1
                _update()

        if bar:
            bar.set(frac_to)

        suspicious = sorted(d for d in all_dlls if not _is_system_dll(d))
        return ("ok", suspicious)
    finally:
        _k32.CloseHandle(handle)
