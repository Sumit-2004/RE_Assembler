"""Part 1 end-to-end pipeline for one DLL: extract -> explain -> render -> report.

Runs the fixed pipeline from the plan: pull every function with radare2, explain
each block (then each function) with Qwen bottom-up, draw the CFGs, and write an
HTML/Markdown report. Explanations are cached by block hash in SQLite so re-runs
are instant.

    python pipeline.py path/to/test_O0.dll --out out/ --limit 10

Needs the full Linux toolchain (radare2 + r2ghidra + Ollama). The static triage
header always works; the explain/render stages degrade with a clear message if a
backend is missing.
"""
import argparse
import hashlib
import json
import os
import sqlite3

from dll_analyzer import disasm, explain, render, tools


def _cache(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS notes (hash TEXT PRIMARY KEY, json TEXT)")
    return conn


def _block_hash(block: dict) -> str:
    return hashlib.sha256("\n".join(block.get("asm", [])).encode()).hexdigest()


def run(path: str, out_dir: str = "out", limit: int = 0) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    triage = tools.triage_dll(path)
    if triage["runtime"] == ".NET":
        return {"triage": triage, "note": "managed DLL -- use the .NET branch (dll_analyzer.dotnet)"}

    import_names = [i["function"] for i in tools.list_imports(path)]
    dump = disasm.extract(path)
    cache = _cache(os.path.join(out_dir, "cache.sqlite"))

    func_summaries = {}
    functions = dump["functions"][:limit] if limit else dump["functions"]
    for func in functions:
        exported = any(func["name"].endswith(e["name"]) for e in tools.list_exports(path))
        notes = {}
        for block in func["blocks"]:
            h = _block_hash(block)
            row = cache.execute("SELECT json FROM notes WHERE hash=?", (h,)).fetchone()
            if row:
                note = json.loads(row[0])
            else:
                note = explain.explain_block(block, func["name"], exported,
                                             import_names, strings=[],
                                             pseudo_c=func.get("pseudo_c", ""),
                                             arch=triage["arch"])
                cache.execute("INSERT OR REPLACE INTO notes VALUES (?,?)", (h, json.dumps(note)))
                cache.commit()
            notes[block["addr"]] = note
        fsumm = explain.explain_function(func, import_names, notes, exported)
        func_summaries[func["name"]] = fsumm.get("summary", "")
        render.render_svg(func, notes, out_dir)
        render.render_html(func, notes, out_dir)

    overview = explain.explain_dll(func_summaries)
    report = {"triage": triage, "overview": overview, "functions": func_summaries}
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("dll")
    ap.add_argument("--out", default="out")
    ap.add_argument("--limit", type=int, default=0, help="explain only the first N functions")
    args = ap.parse_args()
    print(json.dumps(run(args.dll, args.out, args.limit), indent=2))
