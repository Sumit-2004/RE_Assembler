"""High-level capability and string extraction with capa and FLOSS (Part 2).

capa gives a rule-based map of behaviour ("encrypts data using AES", "creates a
service") tagged with ATT&CK and the addresses where each match fired. FLOSS
recovers strings, including stack- and obfuscation-decoded ones. Both let the
agent decide where to look before spending model calls on individual functions.

Both tools shell out read-only; neither runs the binary. They install on the
Linux VM: pip install flare-capa flare-floss.
"""
import json
import subprocess

from . import backends

_CAPA_HINT = "pip install flare-capa (and fetch its rules once: capa downloads them on first run)"
_FLOSS_HINT = "pip install flare-floss"


def find_capabilities(path: str) -> dict:
    """Run capa and return its matches grouped as rule name, ATT&CK tags, addresses.

    Args:
        path: absolute path to the DLL
    """
    backends.require("capa", _CAPA_HINT)
    proc = subprocess.run(["capa", "-j", path], capture_output=True, text=True, check=False)
    if proc.returncode != 0 and not proc.stdout:
        raise backends.BackendMissing(f"capa failed: {proc.stderr.strip()[:300]}")
    data = json.loads(proc.stdout)
    matches = []
    for rule_name, rule in data.get("rules", {}).items():
        meta = rule.get("meta", {})
        attack = [a.get("id") or a.get("technique") for a in meta.get("attack", [])]
        addrs = []
        for loc, _ in rule.get("matches", []):
            value = loc.get("value") if isinstance(loc, dict) else loc
            if isinstance(value, int):
                addrs.append(hex(value))
        matches.append({"rule": rule_name, "namespace": meta.get("namespace", ""),
                        "attack": [a for a in attack if a], "addresses": addrs})
    return {"total": len(matches), "matches": matches}


def search_strings(path: str, regex: str = "") -> dict:
    """Extract strings with FLOSS and optionally filter them by regex.

    Args:
        path: absolute path to the DLL
        regex: optional case-insensitive pattern; empty returns all strings
    """
    import re
    backends.require("floss", _FLOSS_HINT)
    proc = subprocess.run(["floss", "-j", path], capture_output=True, text=True, check=False)
    if not proc.stdout:
        raise backends.BackendMissing(f"floss failed: {proc.stderr.strip()[:300]}")
    data = json.loads(proc.stdout)
    strings = data.get("strings", data)
    pattern = re.compile(regex, re.IGNORECASE) if regex else None
    out = []
    for kind in ("static_strings", "stack_strings", "tight_strings", "decoded_strings"):
        for s in (strings.get(kind, []) if isinstance(strings, dict) else []):
            text = s.get("string", s) if isinstance(s, dict) else s
            if pattern and not pattern.search(text):
                continue
            out.append({"string": text, "decoded": kind != "static_strings",
                        "address": hex(s["address"]) if isinstance(s, dict) and "address" in s else None})
    return {"total": len(out), "strings": out}
