"""Terminal launcher for the AI Assembly Explainer.

Run `python run.py` and pick from a menu instead of remembering commands. Pure
stdlib, so it works in Windows CMD/PowerShell and in WSL/Linux. Each action
checks the backends it needs first and prints the install hint if one is missing,
so nothing crashes with a raw traceback.
"""
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from dll_analyzer import backends  # noqa: E402

# Backends each action needs: (python module, CLI tool on PATH). None = n/a.
CHECKS = {
    "pefile":   ("pefile", None),
    "radare2":  ("r2pipe", "radare2"),
    "ollama":   ("ollama", "ollama"),
    "graphviz": ("graphviz", "dot"),
    "streamlit":("streamlit", "streamlit"),
    "capa":     ("capa", "capa"),
    "floss":    ("floss", "floss"),
    "dnfile":   ("dnfile", None),
    "mingw":    (None, "x86_64-w64-mingw32-gcc"),
}


def _ok(name: str) -> bool:
    mod, cli = CHECKS[name]
    mod_ok = backends.have(mod) if mod else True
    cli_ok = shutil.which(cli) is not None if cli else True
    return mod_ok and cli_ok


def _need(*names: str) -> list[str]:
    return [n for n in names if not _ok(n)]


def _banner() -> None:
    marks = "  ".join(f"{n} {'OK' if _ok(n) else 'x'}"
                      for n in ("pefile", "radare2", "ollama", "graphviz", "streamlit"))
    print("\n" + "=" * 60)
    print("  AI Assembly Explainer")
    print("  The disassembler supplies the facts; Qwen only explains them.")
    print("=" * 60)
    print("  backends:", marks)
    print("-" * 60)


MENU = [
    ("Open the GUI (browse processes + DLLs, click to analyze)", "gui"),
    ("Triage a DLL (static — works on Windows now)", "triage"),
    ("List exports / imports of a DLL", "symbols"),
    ("Explain a DLL end-to-end (pipeline -> graphs + report)", "pipeline"),
    ("Ask the agent a question about a DLL", "agent"),
    ("Launch the Streamlit UI (browser)", "ui"),
    ("Build the benchmark test DLLs", "build"),
    ("Run the tests", "tests"),
    ("Show full setup commands", "setup"),
]


def _ask_path(prompt: str) -> str | None:
    p = input(prompt).strip().strip('"')
    if not p:
        return None
    if not os.path.exists(p):
        print(f"  ! not found: {p}")
        return None
    return p


def _missing_note(names: list[str]) -> None:
    hints = {
        "radare2": "radare2 + r2ghidra (see 'Show setup commands')",
        "ollama": "Ollama + a pulled model (ollama pull qwen2.5-coder:7b)",
        "graphviz": "graphviz (sudo apt install graphviz; pip install graphviz)",
        "streamlit": "pip install streamlit",
        "capa": "pip install flare-capa", "floss": "pip install flare-floss",
        "mingw": "sudo apt install mingw-w64",
    }
    print("  ! needs:", "; ".join(hints.get(n, n) for n in names))
    print("    (these install on the Linux VM / WSL — see 'Show setup commands')")


def do_triage() -> None:
    path = _ask_path("  DLL path: ")
    if not path:
        return
    from dll_analyzer import tools
    try:
        print(json.dumps(tools.triage_dll(path), indent=2))
    except Exception as exc:
        print("  ! error:", exc)


def do_symbols() -> None:
    path = _ask_path("  DLL path: ")
    if not path:
        return
    kind = input("  [e]xports or [i]mports? ").strip().lower()
    filt = input("  filter (optional): ").strip()
    from dll_analyzer import tools
    try:
        rows = tools.list_imports(path, filt) if kind.startswith("i") else tools.list_exports(path, filt)
        print(json.dumps(rows[:200], indent=2))
        print(f"  ({len(rows)} total)")
    except Exception as exc:
        print("  ! error:", exc)


def do_pipeline() -> None:
    miss = _need("radare2", "ollama")
    if miss:
        _missing_note(miss)
        return
    path = _ask_path("  DLL path: ")
    if not path:
        return
    limit = input("  explain first N functions (blank = all): ").strip()
    from dll_analyzer import pipeline
    out = os.path.join(HERE, "out")
    try:
        result = pipeline.run(path, out, int(limit) if limit else 0)
        print(json.dumps(result.get("triage", result), indent=2))
        print(f"  graphs + report written to {out}")
    except Exception as exc:
        print("  ! error:", exc)


def do_agent() -> None:
    miss = _need("ollama")
    if miss:
        _missing_note(miss)
        return
    path = _ask_path("  DLL path: ")
    if not path:
        return
    question = input("  question: ").strip()
    if not question:
        return
    from dll_analyzer.agent import run
    try:
        res = run(question, path)
        print("\n" + res["answer"])
        print(f"\n  ({res['steps']} steps, {len(res['evidence'])} evidence entries)")
    except Exception as exc:
        print("  ! error:", exc)


def do_ui() -> None:
    if _need("streamlit"):
        _missing_note(["streamlit"])
        return
    print("  starting Streamlit — open the URL it prints; Ctrl+C to stop.")
    subprocess.run([sys.executable, "-m", "streamlit", "run", os.path.join(HERE, "app.py")])


def do_build() -> None:
    if _need("mingw"):
        _missing_note(["mingw"])
        return
    subprocess.run(["bash", os.path.join(HERE, "testdlls", "build.sh")])


def do_tests() -> None:
    subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=HERE)


def do_gui() -> None:
    print("  launching the GUI window...")
    subprocess.run([sys.executable, os.path.join(HERE, "gui.py")])


def do_setup() -> None:
    print(SETUP_TEXT)


SETUP_TEXT = r"""
--- Windows, works now ---
  python -m pip install -r requirements.txt

--- Full pipeline (run in WSL / Linux) ---
  sudo apt install -y git build-essential graphviz python3-pip python3-venv mingw-w64
  git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh
  r2pm -ci r2ghidra
  curl -fsSL https://ollama.com/install.sh | sh
  ollama pull qwen2.5-coder:7b
  ollama pull qwen2.5:14b
  python3 -m venv venv && source venv/bin/activate
  pip install -r requirements-full.txt

--- Drive the tools from Claude Code ---
  claude mcp add dll-analyzer -- python server.py
"""

ACTIONS = {
    "gui": do_gui,
    "triage": do_triage, "symbols": do_symbols, "pipeline": do_pipeline,
    "agent": do_agent, "ui": do_ui, "build": do_build, "tests": do_tests,
    "setup": do_setup,
}


def main() -> None:
    while True:
        _banner()
        for i, (label, _) in enumerate(MENU, 1):
            print(f"  {i}) {label}")
        print("  q) Quit")
        choice = input("\n  choose: ").strip().lower()
        if choice in ("q", "quit", "exit"):
            print("  bye.")
            return
        if choice.isdigit() and 1 <= int(choice) <= len(MENU):
            print()
            ACTIONS[MENU[int(choice) - 1][1]]()
            input("\n  [enter] to return to menu...")
        else:
            print("  ? pick a number or q")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n  bye.")
