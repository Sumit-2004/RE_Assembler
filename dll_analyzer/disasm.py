"""Disassembly, CFG and pseudo-C extraction with radare2 (Part 1, Phase 2).

radare2 supplies the facts; the LLM never disassembles. Each binary is opened
once and the r2pipe session is cached, keyed by the file's SHA-256, so the agent
can chain many tool calls against the same DLL without re-analysing it.

Every address is returned as a hex string. Nothing here executes the binary:
r2pipe opens it read-only and only static analysis commands are issued.

Needs radare2 (+ the r2ghidra plugin for pseudo-C) and the r2pipe package,
which install on the Linux VM. See the README.
"""
import hashlib

from . import backends

_R2_HINT = (
    "install radare2 (git clone https://github.com/radareorg/radare2 && "
    "radare2/sys/install.sh), the r2ghidra plugin (r2pm -ci r2ghidra), and "
    "pip install r2pipe"
)

# Open sessions keyed by SHA-256 so repeated tool calls reuse one analysis.
_SESSIONS: dict[str, object] = {}


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def session(path: str):
    """Return a cached, fully analysed r2pipe session for ``path``."""
    key = _sha256(path)
    r2 = _SESSIONS.get(key)
    if r2 is None:
        r2pipe = backends.require("r2pipe", _R2_HINT)
        r2 = r2pipe.open(path, flags=["-2"])  # -2 silences r2's stderr banner
        r2.cmd("e asm.syntax=intel")
        r2.cmd("aaa")  # full analysis: functions, blocks, xrefs
        _SESSIONS[key] = r2
    return r2


def close_all() -> None:
    """Quit every cached radare2 session (used on shutdown and in tests)."""
    for r2 in _SESSIONS.values():
        try:
            r2.quit()
        except Exception:  # pragma: no cover - best effort cleanup
            pass
    _SESSIONS.clear()


def _func_addr(f: dict) -> int:
    # The key name differs between r2 versions.
    return f.get("addr", f.get("offset"))


def _blocks(r2, func_addr: int) -> list[dict]:
    blocks = []
    for b in r2.cmdj(f"afbj @ {func_addr}") or []:
        ops = r2.cmdj(f"pDj {b['size']} @ {b['addr']}") or []
        blocks.append({
            "addr": hex(b["addr"]),
            "asm": [o.get("disasm", "") for o in ops],
            "calls": [o["disasm"] for o in ops if o.get("type") in ("call", "ucall")],
            "jump": hex(b["jump"]) if "jump" in b else None,
            "fail": hex(b["fail"]) if "fail" in b else None,
        })
    return blocks


def list_functions(path: str, name_filter: str = "", page: int = 0, page_size: int = 100) -> dict:
    """List functions radare2 found, paged.

    Args:
        path: absolute path to the DLL
        name_filter: optional case-insensitive substring to match on the name
        page: zero-based page index
        page_size: functions per page
    """
    r2 = session(path)
    rows = []
    for f in r2.cmdj("aflj") or []:
        name = f.get("name", "")
        if name_filter.lower() in name.lower():
            rows.append({
                "name": name,
                "addr": hex(_func_addr(f)),
                "size": f.get("size", 0),
                "block_count": f.get("nbbs", 0),
            })
    start = page * page_size
    return {"total": len(rows), "page": page, "page_size": page_size,
            "functions": rows[start:start + page_size]}


def get_function(path: str, address: str) -> dict:
    """Return one function's basic blocks, CFG edges, calls and pseudo-C.

    Args:
        path: absolute path to the DLL
        address: function address as a hex string, e.g. '0x180001000'
    """
    r2 = session(path)
    addr = int(address, 16)
    info = (r2.cmdj(f"afij @ {addr}") or [{}])[0]
    return {
        "name": info.get("name", ""),
        "addr": hex(addr),
        "size": info.get("size", 0),
        "blocks": _blocks(r2, addr),
        "pseudo_c": r2.cmd(f"pdg @ {addr}") or "",  # needs r2ghidra
    }


def xrefs_to(path: str, target: str) -> list[dict]:
    """List every call site / reference to a function, address or imported API.

    Args:
        path: absolute path to the DLL
        target: a hex address, a function name, or an imported API name
    """
    r2 = session(path)
    # Resolve a symbol name to an address; a hex string passes straight through.
    addr = target if target.startswith("0x") else (r2.cmd(f"?v {target}") or "").strip()
    if not addr or addr == "0x0":
        return []
    out = []
    for x in r2.cmdj(f"axtj {addr}") or []:
        out.append({"from": hex(x["from"]), "type": x.get("type", ""),
                    "func": x.get("fcn_name", ""), "opcode": x.get("opcode", "")})
    return out


def extract(path: str) -> dict:
    """Extract the whole DLL: arch, exports, imports and every function.

    This is the Part 1 Phase 2 dump that the explainer and renderer consume.

    Args:
        path: absolute path to the DLL
    """
    r2 = session(path)
    info = r2.cmdj("ij") or {}
    out = {
        "arch": info.get("bin", {}).get("arch"),
        "bits": info.get("bin", {}).get("bits"),
        "exports": r2.cmdj("iEj") or [],
        "imports": r2.cmdj("iij") or [],
        "functions": [],
    }
    for f in r2.cmdj("aflj") or []:
        addr = _func_addr(f)
        out["functions"].append({
            "name": f.get("name", ""),
            "addr": hex(addr),
            "blocks": _blocks(r2, addr),
            "pseudo_c": r2.cmd(f"pdg @ {addr}") or "",
        })
    return out
