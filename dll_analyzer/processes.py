"""Enumerate running processes and their loaded DLLs on Windows (for the GUI).

Uses the ToolHelp32 API through ctypes, so there is no dependency beyond the
standard library. Everything that touches the Windows API is called lazily
inside functions, so this module still imports on Linux (handy for syntax checks
and for the Linux pipeline), raising a clear error only if a Windows-only call is
actually made off Windows.

Also provides a plain filesystem scan (scan_dlls) that works on any platform.
"""
import ctypes
import os
import sys

# ToolHelp type aliases, defined without ctypes.wintypes so this imports anywhere.
DWORD = ctypes.c_ulong
WCHAR = ctypes.c_wchar
MAX_PATH = 260

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", DWORD), ("cntUsage", DWORD), ("th32ProcessID", DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", DWORD), ("cntThreads", DWORD),
        ("th32ParentProcessID", DWORD), ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", DWORD), ("szExeFile", WCHAR * MAX_PATH),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", DWORD), ("th32ModuleID", DWORD), ("th32ProcessID", DWORD),
        ("GlblcntUsage", DWORD), ("ProccntUsage", DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)), ("modBaseSize", DWORD),
        ("hModule", ctypes.c_void_p), ("szModule", WCHAR * 256),
        ("szExePath", WCHAR * MAX_PATH),
    ]


def _kernel32():
    if sys.platform != "win32":
        raise RuntimeError("process/module enumeration is Windows-only; "
                           "use the Folder scan tab, or run on Windows.")
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    k32.CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
    return k32


def list_processes() -> list[dict]:
    """Return every running process as {pid, name}, sorted by name."""
    k32 = _kernel32()
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    out = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = k32.Process32FirstW(ctypes.c_void_p(snap), ctypes.byref(entry))
        while ok:
            out.append({"pid": int(entry.th32ProcessID), "name": entry.szExeFile})
            ok = k32.Process32NextW(ctypes.c_void_p(snap), ctypes.byref(entry))
    finally:
        k32.CloseHandle(ctypes.c_void_p(snap))
    out.sort(key=lambda p: p["name"].lower())
    return out


def list_modules(pid: int) -> list[dict]:
    """Return the DLLs loaded by a process as {name, path, base}.

    Args:
        pid: the target process id

    Some system / elevated processes deny access; those raise OSError and the
    GUI simply shows an empty list with a note.
    """
    k32 = _kernel32()
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, DWORD(pid))
    if snap == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    out = []
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
        ok = k32.Module32FirstW(ctypes.c_void_p(snap), ctypes.byref(entry))
        while ok:
            name = entry.szModule
            if name.lower().endswith(".dll"):  # skip the main .exe image itself
                out.append({"name": name, "path": entry.szExePath,
                            "base": hex(ctypes.addressof(entry.modBaseAddr.contents))
                                    if entry.modBaseAddr else "0x0"})
            ok = k32.Module32NextW(ctypes.c_void_p(snap), ctypes.byref(entry))
    finally:
        k32.CloseHandle(ctypes.c_void_p(snap))
    out.sort(key=lambda m: m["name"].lower())
    return out


def scan_dlls(folder: str, recursive: bool = False, limit: int = 20000) -> list[dict]:
    """List *.dll files under a folder as {name, path} (works on any platform).

    Args:
        folder: directory to scan
        recursive: descend into subfolders
        limit: stop after this many hits so a whole-drive scan stays responsive
    """
    out = []
    if recursive:
        for root, _dirs, files in os.walk(folder):
            for f in files:
                if f.lower().endswith(".dll"):
                    out.append({"name": f, "path": os.path.join(root, f)})
                    if len(out) >= limit:
                        out.sort(key=lambda m: m["name"].lower())
                        return out
    else:
        try:
            with os.scandir(folder) as it:
                for e in it:
                    if e.is_file() and e.name.lower().endswith(".dll"):
                        out.append({"name": e.name, "path": e.path})
        except OSError:
            pass
    out.sort(key=lambda m: m["name"].lower())
    return out


# Default folders worth offering in the GUI's scan tab.
def default_dll_dirs() -> list[str]:
    win = os.environ.get("SystemRoot", r"C:\Windows")
    cands = [os.path.join(win, "System32"), os.path.join(win, "SysWOW64")]
    return [d for d in cands if os.path.isdir(d)]
