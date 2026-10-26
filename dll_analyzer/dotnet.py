"""The .NET branch: detect managed DLLs and decompile them (Part 2, Week 9).

.NET DLLs are CIL bytecode, not native assembly, so they skip the radare2/Qwen
pipeline entirely. dnfile reads the CLR metadata (types, methods, P/Invoke
declarations) and ilspycmd decompiles straight to C#. triage_dll already sets
runtime == ".NET"; this module is what the agent routes those files to.

Needs: pip install dnfile, and the dotnet tool ilspycmd on PATH
(dotnet tool install -g ilspycmd).
"""
import subprocess

from . import backends

_DNFILE_HINT = "pip install dnfile"
_ILSPY_HINT = "dotnet tool install -g ilspycmd (needs the .NET SDK)"


def is_dotnet(path: str) -> bool:
    """True if the PE carries a CLR header (managed code)."""
    dnfile = backends.require("dnfile", _DNFILE_HINT)
    try:
        pe = dnfile.dnPE(path)
        return getattr(pe, "net", None) is not None
    except Exception:
        return False


def inspect_dotnet(path: str, type_filter: str = "") -> dict:
    """List .NET types, methods and P/Invoke declarations from CLR metadata.

    Args:
        path: absolute path to the managed DLL
        type_filter: optional case-insensitive substring to match a type name
    """
    dnfile = backends.require("dnfile", _DNFILE_HINT)
    pe = dnfile.dnPE(path)
    types, pinvokes = [], []
    mdt = pe.net.mdtables
    for row in getattr(mdt, "TypeDef", []) or []:
        name = f"{row.TypeNamespace}.{row.TypeName}".strip(".")
        if type_filter.lower() in name.lower():
            methods = [m.Name for m in getattr(row, "MethodList", [])]
            types.append({"type": name, "methods": methods})
    for row in getattr(mdt, "ImplMap", []) or []:  # P/Invoke declarations
        pinvokes.append({"entry": getattr(row, "ImportName", ""),
                         "module": getattr(getattr(row, "ImportScope", None), "Name", "")})
    return {"total_types": len(types), "types": types, "pinvokes": pinvokes}


def decompile_csharp(path: str, type_name: str = "") -> str:
    """Decompile the assembly to C# with ilspycmd and return the source text.

    Args:
        path: absolute path to the managed DLL
        type_name: optional fully-qualified type to limit the output
    """
    cmd = ["ilspycmd", path]
    if type_name:
        cmd += ["-t", type_name]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise backends.BackendMissing(f"ilspycmd failed ({_ILSPY_HINT}): {proc.stderr.strip()[:300]}")
    return proc.stdout
