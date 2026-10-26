# AI Assembly Explainer

A local tool that explains Windows DLLs in plain English, and a REA-style agent
that answers questions about them with evidence. The disassembler produces the
facts; a local Qwen model only explains them. Based on the project plan
`AI Assembly Explainer — Project Plan.pdf`.

**Core idea:** stages 1–4 are ordinary code and always correct; only the explain
stage uses the model, and a validator catches it when it names something that is
not in the assembly. Every claim in the agent's report cites the tool call,
address and bytes it came from.

## Layout

```
dll_analyzer/
  tools.py         static triage / exports / imports            (pefile, Windows-ok)
  disasm.py        functions, basic blocks, CFG, pseudo-C        (radare2 + r2ghidra)
  explain.py       Qwen block/function/DLL notes + name check    (Ollama)
  render.py        Graphviz SVG + interactive Cytoscape HTML      (graphviz)
  capabilities.py  capa matches + FLOSS strings                  (flare-capa/floss)
  dotnet.py        .NET detection + ilspycmd C#                  (dnfile/ilspycmd)
  evidence.py      SQLite evidence log, E-ids, support check     (stdlib)
  report.py        observed/inferred/unknown report, validator   (stdlib)
  registry.py      the one shared tool list
  agent.py         local Qwen tool-calling agent loop            (Ollama)
  backends.py      lazy backend imports (never break the import)
pipeline.py        Part 1 end-to-end: extract -> explain -> render -> report
server.py          Part 2 MCP server (Claude Code / Cursor / any client)
app.py             Streamlit UI
testdlls/          testlib.c + build.sh -> four .dll variants
benchmark/         questions.yaml with answer keys
tests/             test_tools.py (needs Windows), test_validation.py (anywhere)
```

Backend imports are lazy: the package imports with only `pefile` present, and
each stage raises one clear "install X" message if its tool is missing. So the
static layer and the stdlib logic run on Windows today; the rest runs once the
Linux toolchain is installed.

## Status

| Plan section | Module | Status |
|---|---|---|
| Part 2 Wk2: triage, exports, imports | `tools.py` | Done, tested on Windows |
| GUI: process/DLL browser + IDA-style CFG graph | `gui.py`, `disasm_view.py`, `nativedisasm.py` | Done; Capstone graph runs on Windows |
| Part 1 Ph2: radare2 extraction, CFG, xrefs | `disasm.py` | Code done; needs radare2 (VM) |
| Part 1 Ph3: block/function/DLL explain + validator | `explain.py` | Code done; needs Ollama |
| Part 1 Ph4: Graphviz SVG + Cytoscape HTML | `render.py` | Code done; HTML needs no backend |
| Part 1 Ph5: Streamlit UI | `app.py` | Code done; needs full stack |
| Part 1 Ph6: test DLLs + benchmark | `testdlls/`, `benchmark/` | Source + build script done |
| Part 2 Wk5: MCP server | `server.py` | Code done; needs `mcp[cli]` |
| Part 2 Wk6: Qwen agent loop | `agent.py` | Code done; needs Ollama |
| Part 2 Wk7: evidence log, labels, validator | `evidence.py`, `report.py` | Done, tested anywhere |
| Part 2 Wk8: capa, FLOSS | `capabilities.py` | Code done; needs flare tools |
| Part 2 Wk9: .NET branch | `dotnet.py` | Code done; needs dnfile/ilspycmd |

## Easiest way: the GUI (Windows)

```bash
python gui.py          # or double-click run_gui.bat / gui.pyw
```

A windowed DLL browser so you never hunt for paths:

- **Running processes** tab — pick a process, see every DLL it has loaded with
  its full path on disk (a mini process-manager view).
- **Folder scan** tab — scan System32 / SysWOW64 or any folder (optionally
  recursive), with a live filter box.

Select any DLL and the buttons analyse it in place:
`Triage`, `Exports`, `Imports` and **`Disassemble (graph)`** run now on Windows;
`Reverse-engineer` runs the full pipeline if the Linux stack is present, otherwise
copies the exact WSL command for that file to your clipboard. `Open folder` /
`Copy path` for the rest.

### IDA/Ghidra-style graph view (`Disassemble (graph)`)

Opens a window with a function list, a **control-flow graph** (basic blocks as
boxes, IDA-coloured edges: blue = unconditional, green = branch taken, red =
fall-through), a flat **disassembly** tab, and a **C/pseudocode** panel. The
disassembler is Capstone (`pip install capstone`), so the graph and the C-style
skeleton work on Windows with **no WSL**. The "AI explain" button fills the C
panel with Qwen's plain-English reconstruction, grounded on the assembly, when a
local Ollama is reachable (a WSL `ollama serve` counts — localhost forwards into
Windows). Real decompilation to C is Ghidra/Hex-Rays territory; the skeleton
shows the true branch structure and the LLM supplies intent.

## Or the terminal menu

```bash
python run.py
```

A text menu with everything — GUI, triage, pipeline, agent, UI, build, tests. It
shows which backends are installed and, if you pick something that needs a tool
you don't have yet, tells you exactly what to install instead of crashing. No
need to remember any of the commands below.

## Setup (Windows, what works now)

```bash
python -m pip install -r requirements.txt
python run.py                                     # then pick 1 (triage) or 2 (symbols)
python -m unittest discover -s tests -v           # test_validation runs; test_tools needs Windows DLLs
```

Triage a DLL or list its symbols:

```bash
python -m dll_analyzer.tools triage  "C:/Windows/System32/kernel32.dll"
python -m dll_analyzer.tools exports "C:/Windows/System32/kernel32.dll" CreateFile
python -m dll_analyzer.tools imports "C:/Windows/System32/kernel32.dll" ntdll
```

## Setup (Linux VM, the full pipeline)

```bash
sudo apt install -y git build-essential graphviz python3-pip python3-venv mingw-w64
git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh
r2pm -ci r2ghidra                                 # decompiler plugin (pseudo-C)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:7b                       # explainer
ollama pull qwen2.5:14b                            # agent planner (or :7b)
python3 -m venv venv && source venv/bin/activate
pip install -r requirements-full.txt
```

Build the benchmark DLLs, then run the pipeline and the agent:

```bash
bash testdlls/build.sh
python pipeline.py testdlls/build/test_O0.dll --out out/ --limit 10
python -c "from dll_analyzer.agent import run; print(run('Does this DLL touch the registry?', 'testdlls/build/test_O0.dll')['answer'])"
streamlit run app.py
```

Register the MCP server with Claude Code to test the tools with a strong model first:

```bash
claude mcp add dll-analyzer -- python /absolute/path/server.py
```

**Important Ollama setting:** the default context window is tiny. `explain.py`
and `agent.py` already set `num_ctx` (16384 / 32768); keep it, or long functions
get silently truncated.

## Scope and ethics

Analyse only DLLs you compiled yourself, open-source libraries, or software whose
licence permits reverse engineering — many commercial EULAs forbid it. Packed or
obfuscated binaries (VMProtect, Themida) are out of scope; UPX files can be
unpacked first with `upx -d`. .NET DLLs are bytecode, detected by `triage_dll`
and routed to the `dotnet` branch. State this in the report; examiners look for it.
```
