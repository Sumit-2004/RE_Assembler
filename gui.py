"""Windows GUI for the AI Assembly Explainer (Tkinter, no dependencies).

Two ways to find a DLL without hunting for paths:
  * Running processes -- pick a process, see every DLL it has loaded, with the
    full path on disk (a mini process-manager view).
  * Folder scan -- scan System32 / SysWOW64 or any folder (optionally recursive)
    and list every .dll with its location.

Select any DLL and the buttons analyse it in place: Triage, Exports and Imports
run now on Windows (pefile). "Reverse-engineer" needs the Linux stack
(radare2 + Qwen); when it is not present the GUI hands you the exact WSL command
for that file, so the deep analysis is still one copy-paste away.

Run it:  python gui.py      (or double-click gui.pyw / run_gui.bat)
"""
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dll_analyzer import backends, processes, tools  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def to_wsl_path(win_path: str) -> str:
    """C:\\Users\\x -> /mnt/c/Users/x so the Windows path works in WSL."""
    p = win_path.replace("\\", "/")
    if len(p) > 1 and p[1] == ":":
        p = f"/mnt/{p[0].lower()}{p[2:]}"
    return p


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AI Assembly Explainer — DLL Browser")
        self.geometry("1100x720")
        self.selected_path = tk.StringVar(value="")
        self._jobs: "queue.Queue" = queue.Queue()
        self._build()
        self.after(100, self._drain_jobs)

    # ---- layout ---------------------------------------------------------
    def _build(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=6, pady=(6, 0))
        nb.add(self._proc_tab(nb), text="  Running processes  ")
        nb.add(self._scan_tab(nb), text="  Folder scan  ")
        self._action_bar()
        self._output()

    def _proc_tab(self, parent):
        frame = ttk.Frame(parent)
        paned = ttk.PanedWindow(frame, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=4, pady=4)

        left = ttk.Frame(paned)
        ttk.Button(left, text="Refresh processes", command=self.load_processes).pack(fill="x")
        self.proc_tree = self._tree(left, ("pid", "name"), (70, 240))
        self.proc_tree.bind("<<TreeviewSelect>>", self.on_process_select)
        paned.add(left, weight=1)

        right = ttk.Frame(paned)
        ttk.Label(right, text="DLLs loaded by the selected process:").pack(anchor="w")
        self.mod_tree = self._tree(right, ("name", "path"), (220, 560))
        self.mod_tree.bind("<<TreeviewSelect>>", lambda e: self._pick(self.mod_tree, "path"))
        paned.add(right, weight=2)
        return frame

    def _scan_tab(self, parent):
        frame = ttk.Frame(parent)
        bar = ttk.Frame(frame)
        bar.pack(fill="x", padx=4, pady=4)
        self.scan_dir = tk.StringVar(value=(processes.default_dll_dirs() or [os.getcwd()])[0])
        ttk.Entry(bar, textvariable=self.scan_dir).pack(side="left", fill="x", expand=True)
        ttk.Button(bar, text="Browse", command=self._browse).pack(side="left", padx=2)
        self.recursive = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="recurse", variable=self.recursive).pack(side="left")
        ttk.Button(bar, text="Scan", command=self.load_scan).pack(side="left", padx=2)

        filt = ttk.Frame(frame)
        filt.pack(fill="x", padx=4)
        ttk.Label(filt, text="filter:").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._apply_filter())
        ttk.Entry(filt, textvariable=self.filter_var).pack(side="left", fill="x", expand=True)

        self.scan_tree = self._tree(frame, ("name", "path"), (260, 720))
        self.scan_tree.bind("<<TreeviewSelect>>", lambda e: self._pick(self.scan_tree, "path"))
        self._scan_rows: list[dict] = []
        return frame

    def _tree(self, parent, cols, widths):
        tree = ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse")
        for c, w in zip(cols, widths):
            tree.heading(c, text=c.upper())
            tree.column(c, width=w, anchor="w")
        vs = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vs.set)
        tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        return tree

    def _action_bar(self):
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=6, pady=4)
        ttk.Label(bar, text="Selected:").pack(side="left")
        ttk.Entry(bar, textvariable=self.selected_path, state="readonly").pack(
            side="left", fill="x", expand=True, padx=4)
        for text, cmd in (
            ("Triage", lambda: self._run(tools.triage_dll, "triage")),
            ("Exports", lambda: self._run(tools.list_exports, "exports")),
            ("Imports", lambda: self._run(tools.list_imports, "imports")),
            ("Disassemble (graph)", self.disassemble),
            ("Reverse-engineer", self.reverse_engineer),
            ("Open folder", self.open_folder),
            ("Copy path", self.copy_path),
        ):
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=2)

    def _output(self):
        wrap = ttk.Frame(self)
        wrap.pack(fill="both", expand=False, padx=6, pady=(0, 6))
        self.out = tk.Text(wrap, height=14, wrap="none", font=("Consolas", 9))
        vs = ttk.Scrollbar(wrap, orient="vertical", command=self.out.yview)
        self.out.configure(yscrollcommand=vs.set)
        self.out.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self._say("Pick a process or scan a folder, select a DLL, then click an action.\n"
                  "Triage / Exports / Imports work on Windows now. Reverse-engineer needs WSL.")

    # ---- data loading ---------------------------------------------------
    def load_processes(self):
        try:
            rows = processes.list_processes()
        except Exception as exc:
            return self._say(f"! {exc}")
        self.proc_tree.delete(*self.proc_tree.get_children())
        for p in rows:
            self.proc_tree.insert("", "end", values=(p["pid"], p["name"]))
        self._say(f"{len(rows)} processes. Select one to list its DLLs.")

    def on_process_select(self, _evt):
        sel = self.proc_tree.selection()
        if not sel:
            return
        pid = int(self.proc_tree.item(sel[0], "values")[0])
        self.mod_tree.delete(*self.mod_tree.get_children())
        try:
            mods = processes.list_modules(pid)
        except Exception as exc:
            return self._say(f"! can't read PID {pid} (often access-denied on system "
                             f"processes): {exc}")
        for m in mods:
            self.mod_tree.insert("", "end", values=(m["name"], m["path"]))
        self._say(f"PID {pid}: {len(mods)} DLLs loaded.")

    def load_scan(self):
        folder = self.scan_dir.get().strip()
        if not os.path.isdir(folder):
            return self._say(f"! not a folder: {folder}")
        self._say(f"scanning {folder}{' (recursive)' if self.recursive.get() else ''} ...")
        self.update_idletasks()
        self._scan_rows = processes.scan_dlls(folder, self.recursive.get())
        self._apply_filter()
        self._say(f"{len(self._scan_rows)} DLLs found in {folder}.")

    def _apply_filter(self):
        needle = self.filter_var.get().lower()
        self.scan_tree.delete(*self.scan_tree.get_children())
        for m in self._scan_rows:
            if needle in m["name"].lower():
                self.scan_tree.insert("", "end", values=(m["name"], m["path"]))

    def _browse(self):
        d = filedialog.askdirectory(initialdir=self.scan_dir.get() or os.getcwd())
        if d:
            self.scan_dir.set(d)

    def _pick(self, tree, col):
        sel = tree.selection()
        if sel:
            idx = tree["columns"].index(col)
            self.selected_path.set(tree.item(sel[0], "values")[idx])

    # ---- actions (run off the UI thread) --------------------------------
    def _run(self, fn, label):
        path = self.selected_path.get()
        if not path:
            return self._say("! select a DLL first.")
        self._say(f"{label} {path} ...")

        def work():
            import json
            try:
                result = fn(path)
                if isinstance(result, list):
                    text = json.dumps(result[:300], indent=2) + f"\n\n({len(result)} total)"
                else:
                    text = json.dumps(result, indent=2)
            except Exception as exc:
                text = f"! error: {exc}"
            self._jobs.put((f"{label}: {path}", text))

        threading.Thread(target=work, daemon=True).start()

    def disassemble(self):
        path = self.selected_path.get()
        if not path:
            return self._say("! select a DLL first.")
        if not backends.have("capstone"):
            return self._say("! the graph view needs Capstone: pip install capstone\n"
                             "  (pure-Python, installs on Windows — no WSL needed).")
        try:
            import disasm_view
            disasm_view.open_for(self, path)
            self._say(f"opened the disassembly graph for {os.path.basename(path)}.")
        except Exception as exc:
            self._say(f"! could not open the graph view: {exc}")

    def reverse_engineer(self):
        path = self.selected_path.get()
        if not path:
            return self._say("! select a DLL first.")
        have_stack = backends.have("r2pipe") and backends.have("ollama")
        if have_stack and os.name != "nt":
            self._say(f"running pipeline on {path} ... (this can take a while)")

            def work():
                try:
                    from dll_analyzer import pipeline
                    pipeline.run(path, os.path.join(HERE, "out"), limit=5)
                    msg = f"done — graphs + report in {os.path.join(HERE, 'out')}"
                except Exception as exc:
                    msg = f"! error: {exc}"
                self._jobs.put(("reverse-engineer", msg))

            threading.Thread(target=work, daemon=True).start()
            return
        # No local stack (the normal Windows case): hand over the WSL command.
        wsl = to_wsl_path(path)
        cmd = (f'wsl bash -lc "cd {to_wsl_path(HERE)} && source venv/bin/activate && '
               f'python pipeline.py \\"{wsl}\\" --out out/ --limit 10"')
        self.clipboard_clear()
        self.clipboard_append(cmd)
        self._say("Deep reverse-engineering (disassembly + Qwen explanations) needs the "
                  "Linux stack (radare2 + Ollama).\nThe exact WSL command for this DLL is "
                  "copied to your clipboard — paste it in a WSL terminal:\n\n  " + cmd +
                  "\n\n(First-time setup: menu option 8 in run.py, or the README.)")

    def open_folder(self):
        path = self.selected_path.get()
        if not path:
            return
        folder = os.path.dirname(path)
        if os.name == "nt":
            subprocess.run(["explorer", "/select,", os.path.normpath(path)])
        else:
            subprocess.run(["xdg-open", folder], check=False)

    def copy_path(self):
        if self.selected_path.get():
            self.clipboard_clear()
            self.clipboard_append(self.selected_path.get())
            self._say("path copied to clipboard.")

    # ---- plumbing -------------------------------------------------------
    def _drain_jobs(self):
        try:
            while True:
                title, text = self._jobs.get_nowait()
                self._say(f"=== {title} ===\n{text}")
        except queue.Empty:
            pass
        self.after(150, self._drain_jobs)

    def _say(self, text):
        self.out.delete("1.0", "end")
        self.out.insert("1.0", text)


def main():
    app = App()
    if os.name == "nt":
        try:
            app.load_processes()
        except Exception:
            pass
    app.mainloop()


if __name__ == "__main__":
    main()
