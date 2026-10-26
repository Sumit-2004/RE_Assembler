"""IDA/Ghidra-style disassembly window (Tkinter canvas CFG + pseudo-C panel).

Opened from the DLL Browser on a selected DLL. Left: the function list. Centre:
a tabbed view with a control-flow graph (basic blocks as boxes, IDA-coloured
edges: blue = unconditional, green = branch taken, red = fall-through) and a flat
disassembly listing. Right: a C-style skeleton of the function, with an
"AI explain" button that fills in Qwen's plain-English reconstruction when a
local Ollama is reachable.

Disassembly is Capstone-based, so the graph works on Windows with no WSL. Only
the AI-explain panel needs Ollama.
"""
import os
import queue
import threading
import tkinter as tk
from tkinter import ttk

from dll_analyzer import backends, nativedisasm
from dll_analyzer.nativedisasm import EDGE_COLORS

MONO = ("Consolas", 9)
NODE_PAD = 6
LAYER_GAP = 70
COL_GAP = 50
MAX_NODE_LINES = 20


class DisasmView(tk.Toplevel):
    def __init__(self, master, path: str):
        super().__init__(master)
        self.path = path
        self.title(f"Disassembly — {os.path.basename(path)}")
        self.geometry("1200x780")
        self.func = None
        self._jobs: "queue.Queue" = queue.Queue()
        self._build()
        self.after(100, self._drain)
        self.load_functions()

    # ---- layout ---------------------------------------------------------
    def _build(self):
        outer = ttk.PanedWindow(self, orient="horizontal")
        outer.pack(fill="both", expand=True)

        left = ttk.Frame(outer, width=240)
        ttk.Label(left, text="Functions (exports first):").pack(anchor="w")
        self.flt = tk.StringVar()
        self.flt.trace_add("write", lambda *_: self._fill_func_list())
        ttk.Entry(left, textvariable=self.flt).pack(fill="x")
        self.func_list = tk.Listbox(left, font=MONO, activestyle="none")
        self.func_list.pack(fill="both", expand=True)
        self.func_list.bind("<<ListboxSelect>>", self.on_func_select)
        outer.add(left, weight=1)

        mid = ttk.PanedWindow(outer, orient="horizontal")
        outer.add(mid, weight=4)

        center = ttk.Frame(mid)
        nb = ttk.Notebook(center)
        nb.pack(fill="both", expand=True)

        graph_tab = ttk.Frame(nb)
        self.canvas = tk.Canvas(graph_tab, bg="#fbfbfd")
        hb = ttk.Scrollbar(graph_tab, orient="horizontal", command=self.canvas.xview)
        vb = ttk.Scrollbar(graph_tab, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(xscrollcommand=hb.set, yscrollcommand=vb.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        vb.grid(row=0, column=1, sticky="ns")
        hb.grid(row=1, column=0, sticky="ew")
        graph_tab.rowconfigure(0, weight=1)
        graph_tab.columnconfigure(0, weight=1)
        nb.add(graph_tab, text="  Graph  ")

        asm_tab = ttk.Frame(nb)
        self.asm = tk.Text(asm_tab, font=MONO, wrap="none")
        av = ttk.Scrollbar(asm_tab, orient="vertical", command=self.asm.yview)
        self.asm.configure(yscrollcommand=av.set)
        self.asm.pack(side="left", fill="both", expand=True)
        av.pack(side="right", fill="y")
        nb.add(asm_tab, text="  Disassembly  ")
        mid.add(center, weight=3)

        right = ttk.Frame(mid)
        head = ttk.Frame(right)
        head.pack(fill="x")
        ttk.Label(head, text="Pseudo-C / explanation").pack(side="left")
        ttk.Button(head, text="AI explain (Ollama)", command=self.ai_explain).pack(side="right")
        self.cpanel = tk.Text(right, font=MONO, wrap="none")
        cv = ttk.Scrollbar(right, orient="vertical", command=self.cpanel.yview)
        self.cpanel.configure(yscrollcommand=cv.set)
        self.cpanel.pack(side="left", fill="both", expand=True)
        cv.pack(side="right", fill="y")
        mid.add(right, weight=2)

        self.status = ttk.Label(self, text="", anchor="w", relief="sunken")
        self.status.pack(fill="x")

    # ---- data -----------------------------------------------------------
    def load_functions(self):
        try:
            self._funcs = nativedisasm.list_code_functions(self.path)
        except Exception as exc:
            self._funcs = []
            self._set_status(f"! {exc}")
        self._fill_func_list()
        if not backends.have("capstone"):
            self._set_status("Capstone not installed — run: pip install capstone  (then reopen)")

    def _fill_func_list(self):
        needle = self.flt.get().lower()
        self.func_list.delete(0, "end")
        self._shown = [f for f in self._funcs if needle in f["name"].lower()]
        for f in self._shown:
            self.func_list.insert("end", f"{f['name']}  {f['addr']}")

    def on_func_select(self, _evt):
        sel = self.func_list.curselection()
        if not sel:
            return
        f = self._shown[sel[0]]
        self._set_status(f"disassembling {f['name']} @ {f['addr']} ...")
        self.update_idletasks()
        try:
            self.func = nativedisasm.disassemble_function(self.path, f["addr"])
        except Exception as exc:
            return self._set_status(f"! {exc}")
        self._draw_graph()
        self._fill_asm()
        self.cpanel.delete("1.0", "end")
        self.cpanel.insert("1.0", nativedisasm.pseudo_skeleton(self.func))
        self._set_status(f"{f['name']}: {len(self.func['blocks'])} blocks, "
                         f"{len(self.func['edges'])} edges ({self.func['arch']})")

    def _fill_asm(self):
        self.asm.delete("1.0", "end")
        for b in self.func["blocks"]:
            self.asm.insert("end", f"{b['addr']}:\n")
            for ins in b["asm"]:
                self.asm.insert("end", f"    {ins}\n")
            self.asm.insert("end", "\n")

    # ---- graph drawing --------------------------------------------------
    def _draw_graph(self):
        c = self.canvas
        c.delete("all")
        blocks = self.func["blocks"]
        if not blocks:
            return
        # layer each block by BFS depth from the entry
        succ = {}
        for b in blocks:
            succ[b["addr"]] = [s for s in (b["jump"], b["fail"]) if s]
        entry = blocks[0]["addr"]
        layer = {entry: 0}
        q = [entry]
        while q:
            a = q.pop(0)
            for s in succ.get(a, []):
                if s not in layer:
                    layer[s] = layer[a] + 1
                    q.append(s)
        for b in blocks:  # unreached-by-BFS fallbacks
            layer.setdefault(b["addr"], max(layer.values(), default=0) + 1)

        # measure nodes
        boxes = {}
        for b in blocks:
            lines = b["asm"][:MAX_NODE_LINES]
            if len(b["asm"]) > MAX_NODE_LINES:
                lines = lines + [f"... (+{len(b['asm']) - MAX_NODE_LINES} more)"]
            w = 8 * max([len(b["addr"])] + [len(x) for x in lines]) + 2 * NODE_PAD
            h = 14 * (len(lines) + 1) + 2 * NODE_PAD
            boxes[b["addr"]] = {"w": w, "h": h, "lines": lines}

        # place: stack layers top-to-bottom, nodes left-to-right within a layer
        by_layer = {}
        for addr, l in layer.items():
            by_layer.setdefault(l, []).append(addr)
        y = 20
        pos = {}
        for l in sorted(by_layer):
            x = 20
            row_h = 0
            for addr in sorted(by_layer[l], key=lambda a: int(a, 16)):
                box = boxes[addr]
                pos[addr] = (x, y)
                x += box["w"] + COL_GAP
                row_h = max(row_h, box["h"])
            y += row_h + LAYER_GAP

        # edges first (behind nodes)
        for e in self.func["edges"]:
            if e["src"] not in pos or e["dst"] not in pos:
                continue
            sx, sy = pos[e["src"]]
            dx, dy = pos[e["dst"]]
            sb, db = boxes[e["src"]], boxes[e["dst"]]
            x1, y1 = sx + sb["w"] / 2, sy + sb["h"]
            x2, y2 = dx + db["w"] / 2, dy
            c.create_line(x1, y1, x2, y2, fill=EDGE_COLORS.get(e["kind"], "#888"),
                          width=2, arrow="last", smooth=True)

        # nodes
        for b in blocks:
            addr = b["addr"]
            x, yy = pos[addr]
            box = boxes[addr]
            c.create_rectangle(x, yy, x + box["w"], yy + box["h"],
                               fill="#ffffff", outline="#33415c", width=1)
            c.create_text(x + NODE_PAD, yy + NODE_PAD, anchor="nw",
                          text=addr, font=(MONO[0], MONO[1], "bold"), fill="#33415c")
            c.create_text(x + NODE_PAD, yy + NODE_PAD + 15, anchor="nw",
                          text="\n".join(box["lines"]), font=MONO, fill="#111")
        c.configure(scrollregion=c.bbox("all"))

    # ---- AI explain -----------------------------------------------------
    def ai_explain(self):
        if not self.func:
            return self._set_status("select a function first.")
        if not backends.have("ollama"):
            wsl = _wsl(self.path)
            self.cpanel.delete("1.0", "end")
            self.cpanel.insert("1.0",
                "// AI explanation needs a local Ollama model.\n"
                "// Install Ollama (ollama.com) + 'ollama pull qwen2.5-coder:7b'.\n"
                "// A WSL Ollama works too: run 'ollama serve' in WSL, then pip install ollama here.\n\n"
                f"// Then this panel reconstructs intent for {self.func['name']} grounded on its asm.\n"
                f"// Deep pipeline on the VM:\n//   python pipeline.py \"{wsl}\" --out out/\n")
            return self._set_status("Ollama not found — see the panel for how to enable AI explain.")
        self._set_status("asking Qwen (this can take a bit) ...")
        func, path = self.func, self.path

        def work():
            try:
                from dll_analyzer import explain, tools
                imports = [i["function"] for i in tools.list_imports(path)]
                notes = {}
                for b in func["blocks"][:25]:
                    note = explain.explain_block(b, func["name"], True, imports,
                                                 strings=[], pseudo_c="", arch=func["arch"])
                    notes[b["addr"]] = note
                fsumm = explain.explain_function(func, imports, notes, exported=True)
                lines = [f"// {func['name']} — AI reconstruction (grounded on the assembly)",
                         f"// {fsumm.get('summary', '')}", "", f"/* {fsumm.get('detail', '')} */", ""]
                for b in func["blocks"][:25]:
                    n = notes[b["addr"]]
                    flag = "  [UNVERIFIED]" if n.get("unverified") else ""
                    lines.append(f"{b['addr']}: {n.get('summary', '')}{flag}")
                self._jobs.put("\n".join(lines))
            except Exception as exc:
                self._jobs.put(f"// error: {exc}")

        threading.Thread(target=work, daemon=True).start()

    # ---- plumbing -------------------------------------------------------
    def _drain(self):
        try:
            while True:
                text = self._jobs.get_nowait()
                self.cpanel.delete("1.0", "end")
                self.cpanel.insert("1.0", text)
                self._set_status("AI explanation ready.")
        except queue.Empty:
            pass
        self.after(150, self._drain)

    def _set_status(self, text):
        self.status.configure(text="  " + text)


def _wsl(win_path: str) -> str:
    p = win_path.replace("\\", "/")
    if len(p) > 1 and p[1] == ":":
        p = f"/mnt/{p[0].lower()}{p[2:]}"
    return p


def open_for(master, path: str) -> None:
    DisasmView(master, path)
