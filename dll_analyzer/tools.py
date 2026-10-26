"""Static triage and symbol listing for Windows PE files (DLLs and EXEs).

Nothing here executes the file or writes to it. Addresses are returned as
hex strings so they can be passed straight into the later radare2 tools.
"""
import datetime
import hashlib
import json
import math
import sys

import pefile

MACHINES = {0x014C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x01C4: "ARMNT"}
IMAGE_FILE_DLL = 0x2000
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040  # ASLR
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100  # DEP
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000  # Control Flow Guard
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14  # CLR header, present only for .NET
PACKED_ENTROPY = 7.2  # sections above this are usually compressed or encrypted


def _open(path: str) -> pefile.PE:
    return pefile.PE(path)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum(c / total * math.log2(c / total) for c in counts if c)


def triage_dll(path: str) -> dict:
    """Summarise a PE file: architecture, flags, sections and packer hints.

    Args:
        path: absolute path to the PE file
    """
    with open(path, "rb") as fh:
        raw = fh.read()
    pe = pefile.PE(data=raw)
    base = pe.OPTIONAL_HEADER.ImageBase
    dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics

    sections = []
    packer_hints = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="replace")
        entropy = round(_entropy(s.get_data()), 2)
        sections.append({"name": name, "virtual_address": hex(base + s.VirtualAddress),
                         "virtual_size": s.Misc_VirtualSize, "entropy": entropy})
        if entropy > PACKED_ENTROPY:
            packer_hints.append(f"section {name} has entropy {entropy}")
        if name.upper().startswith("UPX"):
            packer_hints.append(f"section name {name} looks like UPX")

    is_dotnet = pe.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0
    subsystem = pe.OPTIONAL_HEADER.Subsystem
    pe_info = {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "md5": hashlib.md5(raw).hexdigest(),
        "arch": MACHINES.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)),
        "is_dll": bool(pe.FILE_HEADER.Characteristics & IMAGE_FILE_DLL),
        "timestamp": datetime.datetime.fromtimestamp(
            pe.FILE_HEADER.TimeDateStamp, datetime.timezone.utc).isoformat(),
        "subsystem": pefile.SUBSYSTEM_TYPE.get(subsystem, str(subsystem)),
        "entry_point": hex(base + pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "aslr": bool(dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
        "dep": bool(dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
        "control_flow_guard": bool(dll_chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF),
        "runtime": ".NET" if is_dotnet else "native",
        "sections": sections,
        "packer_hints": packer_hints,
        "export_count": len(_export_symbols(pe)),
        "import_count": sum(len(e.imports) for e in _import_entries(pe)),
    }
    pe.close()
    return pe_info


def _export_symbols(pe: pefile.PE) -> list:
    directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    return directory.symbols if directory else []


def _import_entries(pe: pefile.PE) -> list:
    return getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) + getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", [])


def list_exports(path: str, name_filter: str = "") -> list[dict]:
    """List exported functions of a Windows DLL.

    Args:
        path: absolute path to the DLL
        name_filter: optional case-insensitive substring to match
    """
    pe = _open(path)
    base = pe.OPTIONAL_HEADER.ImageBase
    out = []
    for s in _export_symbols(pe):
        name = s.name.decode(errors="replace") if s.name else f"ord_{s.ordinal}"
        if name_filter.lower() in name.lower():
            out.append({"name": name, "ordinal": s.ordinal,
                        "address": hex(base + s.address),
                        "forwarder": s.forwarder.decode(errors="replace") if s.forwarder else None})
    pe.close()
    return out


def list_imports(path: str, dll_filter: str = "") -> list[dict]:
    """List imported functions, including delay-loaded ones.

    Args:
        path: absolute path to the DLL
        dll_filter: optional substring of the imported DLL name, e.g. 'winhttp'
    """
    pe = _open(path)
    out = []
    for attr, delayed in (("DIRECTORY_ENTRY_IMPORT", False), ("DIRECTORY_ENTRY_DELAY_IMPORT", True)):
        for entry in getattr(pe, attr, []):
            dll = entry.dll.decode(errors="replace")
            if dll_filter.lower() not in dll.lower():
                continue
            for imp in entry.imports:
                function = imp.name.decode(errors="replace") if imp.name else f"ord_{imp.ordinal}"
                out.append({"dll": dll, "delay_load": delayed, "function": function,
                            "iat_address": hex(imp.address)})
    pe.close()
    return out


if __name__ == "__main__":
    # Usage: python -m dll_analyzer.tools <triage|exports|imports> <path> [filter]
    if len(sys.argv) < 3 or sys.argv[1] not in ("triage", "exports", "imports"):
        sys.exit(__doc__.split("\n")[0] + "\n" + "usage: python -m dll_analyzer.tools <triage|exports|imports> <path> [filter]")
    command, target = sys.argv[1], sys.argv[2]
    extra = sys.argv[3] if len(sys.argv) > 3 else ""
    if command == "triage":
        result = triage_dll(target)
    elif command == "exports":
        result = list_exports(target, extra)
    else:
        result = list_imports(target, extra)
    print(json.dumps(result, indent=2))
