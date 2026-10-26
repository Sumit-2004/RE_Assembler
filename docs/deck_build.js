const pptx = require("pptxgenjs");
const p = new pptx();
p.layout = "LAYOUT_WIDE";            // 13.33 x 7.5
const W = 13.33, H = 7.5;

// ---- palette (content-informed: the tool's own CFG edge colours) ----------
const INK = "14202E";     // near-black slate (dark bg)
const INK2 = "1E2E42";    // panel on dark
const PAPER = "FFFFFF";
const PANEL = "F3F6FB";   // light content panel
const TXT = "1B2635";     // dark text on light
const MUTE = "5E6B7B";    // muted
const GREEN = "1FA463";   // branch taken
const BLUE = "2A6BD0";    // unconditional
const RED = "C0392B";     // fall-through
const GOLD = "D99A1C";    // accent / inferred
const HEAD = "Cambria", BODY = "Calibri", MONO = "Courier New";

const notes = {};
function slide(bg) { const s = p.addSlide(); if (bg) s.background = { color: bg }; return s; }
function tb(s, text, o) { s.addText(text, Object.assign({ isTextBox: true, fontFace: BODY, color: TXT }, o)); }

// reusable: a "basic block" card echoing the CFG motif
function block(s, x, y, w, h, title, body, opts = {}) {
  s.addShape(p.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.06,
    fill: { color: opts.fill || PAPER }, line: { color: opts.line || "C9D4E3", width: 1 },
    shadow: { type: "outer", color: "9AA7B8", blur: 5, offset: 2, angle: 90, opacity: 0.28 } });
  if (title) s.addText(title, { isTextBox: true, x: x + 0.12, y: y + 0.08, w: w - 0.24, h: 0.3,
    fontFace: MONO, fontSize: opts.ts || 11, bold: true, color: opts.tc || BLUE, margin: 0 });
  if (body) s.addText(body, { isTextBox: true, x: x + 0.12, y: y + 0.4, w: w - 0.24, h: h - 0.5,
    fontFace: opts.bodyMono ? MONO : BODY, fontSize: opts.bs || 11, color: opts.bc || TXT, margin: 0, valign: "top" });
}
function arrow(s, x1, y1, x2, y2, color) {
  s.addShape(p.ShapeType.line, { x: x1, y: y1, w: x2 - x1, h: y2 - y1,
    line: { color: color || MUTE, width: 2.25, endArrowType: "triangle" } });
}
function kicker(s, text, color) {
  tb(s, text.toUpperCase(), { x: 0.6, y: 0.5, w: 9, h: 0.35, fontFace: MONO, fontSize: 12,
    bold: true, color: color || GREEN, charSpacing: 2, margin: 0 });
}
function title(s, text) {
  tb(s, text, { x: 0.6, y: 0.82, w: 12.1, h: 0.8, fontFace: HEAD, fontSize: 32, bold: true, color: TXT, margin: 0 });
}

// ============================================================ 1. TITLE
(() => {
  const s = slide(INK);
  // motif: mini CFG in the upper-right
  const bx = 9.0;
  block(s, bx + 0.9, 0.55, 2.2, 0.7, "0x18000ab90", "push rbx\nsub rsp, 0x20", { fill: INK2, line: "33465F", tc: "7FB4FF", bc: "C7D3E3", bodyMono: true, bs: 9, ts: 9 });
  block(s, bx + 0.0, 1.75, 2.2, 0.7, "loc_abbc", "add rax, 2\ntest ecx, ecx", { fill: INK2, line: "33465F", tc: "7FB4FF", bc: "C7D3E3", bodyMono: true, bs: 9, ts: 9 });
  block(s, bx + 1.9, 1.75, 2.2, 0.7, "loc_abc4", "test edx, edx\nje 0x...abff", { fill: INK2, line: "33465F", tc: "7FB4FF", bc: "C7D3E3", bodyMono: true, bs: 9, ts: 9 });
  arrow(s, bx + 2.0, 1.25, bx + 1.1, 1.75, GREEN);
  arrow(s, bx + 2.0, 1.25, bx + 3.0, 1.75, RED);
  arrow(s, bx + 1.1, 2.45, bx + 1.1, 2.75, BLUE);

  tb(s, "AI ASSEMBLY EXPLAINER", { x: 0.7, y: 2.5, w: 11.9, h: 1.0, fontFace: HEAD, fontSize: 46, bold: true, color: PAPER, margin: 0 });
  tb(s, "An evidence-grounded reverse-engineering assistant for Windows DLLs", { x: 0.72, y: 3.5, w: 11.5, h: 0.6, fontFace: BODY, fontSize: 20, color: "9FC6F0", margin: 0 });
  tb(s, "The disassembler supplies the facts  ·  the model only explains them  ·  every claim is validated", { x: 0.72, y: 4.12, w: 11.6, h: 0.5, fontFace: BODY, fontSize: 14, italic: true, color: "C7D3E3", margin: 0 });

  s.addShape(p.ShapeType.line, { x: 0.72, y: 5.3, w: 4.5, h: 0, line: { color: GREEN, width: 2 } });
  tb(s, "Project Work — Reverse Engineering", { x: 0.72, y: 5.5, w: 8, h: 0.4, fontFace: MONO, fontSize: 13, bold: true, color: GREEN, margin: 0 });
  tb(s, "Sumit   ·   special.projects@rru.ac.in   ·   Oct 2026", { x: 0.72, y: 6.0, w: 11, h: 0.4, fontFace: BODY, fontSize: 13, color: "9FB0C3", margin: 0 });
  notes.t1 = "Title. Pitch: I built a tool that explains real disassembled Windows DLLs in plain English, grounded on a real disassembler so it can't make up facts. Replace [Your Name] and add the repo link on the last slide.";
  s.addNotes(notes.t1);
})();

// ============================================================ 2. WHY / MOTIVATION
(() => {
  const s = slide(PAPER);
  kicker(s, "Why I built this", GREEN);
  title(s, "From Ghidra, IDA Free & ILSpy — to an explainer");
  const cards = [
    ["Ghidra", "C7E3D0", GREEN, "NSA's free decompiler. Superb pseudo-C and CFGs — but reading them still demands fluent assembly."],
    ["IDA Free", "CFE0F5", BLUE, "The gold-standard graph view and the green/red/blue edge convention I learned RE on."],
    ["ILSpy", "F6E3C2", GOLD, "Turns a .NET DLL straight into C# — the 'just explain it to me' feel I wanted for native code too."],
  ];
  cards.forEach((c, i) => {
    const x = 0.6 + i * 4.15;
    block(s, x, 1.95, 3.85, 2.2, null, null, { line: c[1] });
    s.addShape(p.ShapeType.ellipse, { x: x + 0.25, y: 2.2, w: 0.55, h: 0.55, fill: { color: c[1] }, line: { color: c[2], width: 1.5 } });
    tb(s, c[0][0], { x: x + 0.25, y: 2.24, w: 0.55, h: 0.48, align: "center", fontFace: HEAD, fontSize: 22, bold: true, color: c[2], margin: 0 });
    tb(s, c[0], { x: x + 1.0, y: 2.28, w: 2.7, h: 0.45, fontFace: HEAD, fontSize: 18, bold: true, color: TXT, margin: 0 });
    tb(s, c[3], { x: x + 0.28, y: 2.95, w: 3.3, h: 1.1, fontFace: BODY, fontSize: 13, color: MUTE, margin: 0, valign: "top" });
  });
  block(s, 0.6, 4.55, 12.15, 1.9, null, null, { fill: PANEL, line: "D7E0EC" });
  tb(s, "The gap", { x: 0.9, y: 4.75, w: 4, h: 0.4, fontFace: HEAD, fontSize: 17, bold: true, color: RED, margin: 0 });
  tb(s, [
    { text: "All three show you the code. None ", options: {} },
    { text: "explain what it does", options: { bold: true, color: TXT } },
    { text: " in plain English, fully offline, with guardrails against making things up. So I built a pipeline where a real disassembler produces the facts and a local LLM only narrates them — and a validator catches it when it names something that isn't in the bytes.", options: {} },
  ], { x: 0.9, y: 5.2, w: 11.5, h: 1.1, fontFace: BODY, fontSize: 15, color: MUTE, margin: 0, valign: "top" });
  notes.t2 = "Motivation. I genuinely used Ghidra, IDA Free and ILSpy. They're powerful but assume you can read assembly. ILSpy's instant C# for .NET is the experience I wanted for native DLLs. The gap: none explain intent in plain English, offline, with anti-hallucination guards.";
  s.addNotes(notes.t2);
})();

// ============================================================ 3. SCOPE & GOAL
(() => {
  const s = slide(PAPER);
  kicker(s, "Problem & scope", GREEN);
  title(s, "What it analyses — and the one rule");
  const col = (x, head, color, items) => {
    block(s, x, 1.95, 5.9, 2.75, null, null, { line: "D7E0EC" });
    tb(s, head, { x: x + 0.3, y: 2.12, w: 5, h: 0.4, fontFace: HEAD, fontSize: 17, bold: true, color, margin: 0 });
    tb(s, items.map(t => ({ text: t, options: { bullet: { indent: 14 }, breakLine: true, paraSpaceAfter: 6 } })),
      { x: x + 0.3, y: 2.6, w: 5.3, h: 2.0, fontFace: BODY, fontSize: 13.5, color: TXT, margin: 0, valign: "top" });
  };
  col(0.6, "In scope", GREEN, ["Native x86 / x64 Windows DLLs (PE)", "Static .lib archives and Linux .so (ELF)", ".NET DLLs → ILSpy-style C# branch", "Your own, open-source, or licensed binaries"]);
  col(6.85, "Out of scope", RED, ["Packed / obfuscated (VMProtect, Themida)", "— UPX can be unpacked first (upx -d)", "Running the binary — analysis is read-only", "Guessing facts the tools didn't observe"]);
  block(s, 0.6, 4.95, 12.15, 1.5, null, null, { fill: INK, line: INK });
  tb(s, "GOAL", { x: 0.9, y: 5.12, w: 3, h: 0.35, fontFace: MONO, fontSize: 12, bold: true, color: GREEN, charSpacing: 2, margin: 0 });
  tb(s, "Explain any supported DLL in plain English, 100% offline, where the model may never state a fact the disassembler did not produce.",
    { x: 0.9, y: 5.5, w: 11.5, h: 0.9, fontFace: HEAD, fontSize: 19, italic: true, color: PAPER, margin: 0, valign: "top" });
  notes.t3 = "Scope keeps it a realistic student project. The hard rule — the model never invents facts — is what the whole architecture is built to enforce.";
  s.addNotes(notes.t3);
})();

// ============================================================ 4. CORE PRINCIPLE / TRUST BOUNDARY
(() => {
  const s = slide(PAPER);
  kicker(s, "Core principle", GREEN);
  title(s, "Never let the LLM disassemble");
  tb(s, "Stages 1–4 are ordinary, deterministic code — always correct. Only stage 5 uses the model, and stage 6 catches it when it names something not in the assembly.",
    { x: 0.6, y: 1.7, w: 12.1, h: 0.7, fontFace: BODY, fontSize: 15, color: MUTE, margin: 0 });
  const steps = [
    ["1 Parse", "LIEF / pefile", "det"], ["2 Disassemble", "radare2 · Capstone", "det"],
    ["3 Decompile", "r2ghidra pseudo-C", "det"], ["4 Build context", "calls · strings · C", "det"],
    ["5 Explain", "Qwen2.5-Coder", "ai"], ["6 Validate", "name + JSON check", "val"],
  ];
  const y = 2.75, w = 1.92, gap = 0.08;
  steps.forEach((st, i) => {
    const x = 0.6 + i * (w + gap);
    const isAI = st[2] === "ai", isVal = st[2] === "val";
    const fill = isAI ? GOLD : isVal ? GREEN : INK2;
    block(s, x, y, w, 1.5, null, null, { fill, line: fill });
    tb(s, st[0], { x: x + 0.12, y: y + 0.2, w: w - 0.24, h: 0.4, fontFace: HEAD, fontSize: 14.5, bold: true, color: PAPER, margin: 0 });
    tb(s, st[1], { x: x + 0.12, y: y + 0.75, w: w - 0.24, h: 0.6, fontFace: MONO, fontSize: 9.5, color: isAI ? "2A1E00" : "CFE0F0", margin: 0, valign: "top" });
    if (i < steps.length - 1) arrow(s, x + w, y + 0.75, x + w + gap, y + 0.75, MUTE);
  });
  const legend = (x, c, t) => { s.addShape(p.ShapeType.rect, { x, y: 4.6, w: 0.28, h: 0.28, fill: { color: c } }); tb(s, t, { x: x + 0.38, y: 4.58, w: 4, h: 0.35, fontFace: BODY, fontSize: 13, color: TXT, margin: 0 }); };
  legend(0.6, INK2, "Deterministic — cannot hallucinate");
  legend(5.1, GOLD, "The model — explains only");
  legend(9.0, GREEN, "Validator — rejects invented facts");
  block(s, 0.6, 5.35, 12.15, 1.15, null, null, { fill: PANEL, line: "D7E0EC" });
  tb(s, [
    { text: "Trust boundary:  ", options: { bold: true, color: RED } },
    { text: "everything true about the binary is produced before the model speaks. The LLM reasons over those facts and is checked afterwards — it is the one component that is never trusted on its own.", options: {} },
  ], { x: 0.9, y: 5.55, w: 11.5, h: 0.8, fontFace: BODY, fontSize: 15, color: MUTE, margin: 0, valign: "top" });
  notes.t4 = "The single most important design decision. A 7B model cannot reliably turn bytes into instructions, so it never tries. It only explains facts the disassembler already produced, and the validator checks every claim.";
  s.addNotes(notes.t4);
})();

// ============================================================ 5. ARCHITECTURE — PART 1 PIPELINE
(() => {
  const s = slide(INK);
  kicker(s, "System architecture · Part 1", "7FB4FF");
  tb(s, "The explain pipeline", { x: 0.6, y: 0.82, w: 12, h: 0.8, fontFace: HEAD, fontSize: 32, bold: true, color: PAPER, margin: 0 });
  const row = (y, items) => items.forEach((it, i) => {
    const x = 0.6 + i * 3.15;
    block(s, x, y, 2.85, 1.15, it[0], it[1], { fill: INK2, line: it[2] || "33465F", tc: it[3] || "7FB4FF", bc: "C7D3E3", bs: 11 });
    if (i < items.length - 1) arrow(s, x + 2.85, y + 0.55, x + 3.15, y + 0.55, "6E86A6");
  });
  row(2.0, [["1 · Input", "DLL / LIB / .so\nx86 / x64 native", "33465F"], ["2 · Parse", "arch, exports,\nimports, strings", "33465F"], ["3 · Disassemble", "functions, blocks,\nCFG, pseudo-C", "33465F"], ["4 · Context", "per block: asm +\ncalls, strings, C", "33465F"]]);
  row(3.6, [["7 · Graph + report", "SVG · interactive\nHTML · Markdown", GREEN, "7BE3AC"], ["6 · Validate", "names checked vs asm\nre-ask on mismatch", GREEN, "7BE3AC"], ["5 · Explain", "Qwen2.5-Coder 7B\nstrict JSON output", GOLD, "FFD98A"], ["", "", INK, INK]]);
  // down arrow stage 4 (top-right) -> stage 5 (bottom, 3rd box)
  arrow(s, 11.45, 3.15, 8.35, 3.6, GOLD);
  // bottom row flows right -> left: 5 -> 6 -> 7
  arrow(s, 6.9, 4.175, 6.6, 4.175, "6E86A6");
  arrow(s, 3.75, 4.175, 3.45, 4.175, "6E86A6");
  tb(s, "optional: a Qwen2.5-VL screenshot path can feed the same output", { x: 10.15, y: 4.15, w: 2.55, h: 0.95, fontFace: BODY, fontSize: 10.5, italic: true, color: "8FA3BC", margin: 0, valign: "top" });
  block(s, 0.6, 5.5, 12.15, 1.15, null, null, { fill: "0C1826", line: "2A3C55" });
  tb(s, "Caching:  explanations are keyed by basic-block hash in SQLite — re-runs are instant, and a block explained once is never re-billed to the model.",
    { x: 0.9, y: 5.72, w: 11.5, h: 0.8, fontFace: BODY, fontSize: 14, color: "C7D3E3", margin: 0, valign: "top" });
  notes.t5 = "The Part 1 fixed pipeline. Bottom-up: explain every block, then each function from its block notes, then a whole-DLL overview. The dashed screenshot path (Qwen-VL) is an optional experiment.";
  s.addNotes(notes.t5);
})();

// ============================================================ 6. REFERENCES — GHIDRA & REA
(() => {
  const s = slide(PAPER);
  kicker(s, "Built on prior art", GREEN);
  title(s, "Standing on Ghidra, IDA, ILSpy & REA");
  const rows = [
    ["Ghidra", GREEN, "Decompiler & CFG recovery", "Its decompiler (via the r2ghidra plugin) gives the model pseudo-C context; its basic-block model shapes my extraction."],
    ["IDA Free", BLUE, "Graph view & edge colours", "I emulate its function graph and the green=taken / red=fall-through / blue=unconditional edge convention."],
    ["ILSpy", GOLD, ".NET decompilation", "The managed-code branch: a CLR header routes the DLL to ILSpy-style C# instead of the native pipeline."],
    ["REA", RED, "Agentic, evidence-first RE", "Reverse Engineering Assistant's pattern: the LLM plans which tool to call, tools observe, and every claim carries evidence."],
  ];
  rows.forEach((r, i) => {
    const y = 1.95 + i * 1.12;
    block(s, 0.6, y, 12.15, 1.0, null, null, { line: "D7E0EC" });
    s.addShape(p.ShapeType.roundRect, { x: 0.8, y: y + 0.2, w: 1.9, h: 0.6, rectRadius: 0.05, fill: { color: r[1] } });
    tb(s, r[0], { x: 0.8, y: y + 0.28, w: 1.9, h: 0.45, align: "center", fontFace: HEAD, fontSize: 15, bold: true, color: PAPER, margin: 0 });
    tb(s, r[2], { x: 2.95, y: y + 0.17, w: 3.0, h: 0.7, fontFace: HEAD, fontSize: 13.5, bold: true, color: TXT, margin: 0, valign: "center" });
    tb(s, r[3], { x: 6.1, y: y + 0.13, w: 6.45, h: 0.78, fontFace: BODY, fontSize: 12.5, color: MUTE, margin: 0, valign: "center" });
  });
  notes.t6 = "Credit where due. I didn't reinvent disassembly — I reuse Ghidra/radare2 for facts, borrow IDA's graph UX, route .NET to ILSpy, and take the agent-with-evidence pattern from REA. My contribution is wiring these into an offline, validated, plain-English explainer.";
  s.addNotes(notes.t6);
})();

// ============================================================ 7. TECH STACK
(() => {
  const s = slide(PAPER);
  kicker(s, "Tech stack", GREEN);
  title(s, "Everything free, offline, Python 3.11+");
  const rows = [
    ["Binary parsing", "pefile / LIEF", "Arch, exports, imports, sections, entropy, .NET detection"],
    ["Disassembly (Windows)", "Capstone", "Pure-Python x86/x64 — real CFG recovery with no WSL"],
    ["Disassembly + decompile", "radare2 + r2ghidra", "Functions, CFG, xrefs and pseudo-C on the Linux VM"],
    ["LLM runtime", "Ollama + Qwen2.5-Coder 7B", "Local, offline model that only explains the facts"],
    ["Graphs", "Graphviz + Cytoscape.js", "Static SVG and an interactive clickable CFG"],
    ["Cache / evidence", "SQLite", "Block-hash cache + the agent's tamper-evident evidence log"],
    ["Interfaces", "Tkinter GUI · MCP server", "DLL browser + graph view; same tools for Claude Code"],
  ];
  const y0 = 1.85, rh = 0.68;
  rows.forEach((r, i) => {
    const y = y0 + i * rh;
    if (i % 2 === 0) s.addShape(p.ShapeType.rect, { x: 0.6, y, w: 12.15, h: rh, fill: { color: PANEL }, line: { color: PANEL } });
    tb(s, r[0], { x: 0.8, y: y + 0.08, w: 3.3, h: rh - 0.16, fontFace: BODY, fontSize: 13.5, bold: true, color: TXT, margin: 0, valign: "center" });
    tb(s, r[1], { x: 4.2, y: y + 0.08, w: 3.5, h: rh - 0.16, fontFace: MONO, fontSize: 12.5, color: BLUE, margin: 0, valign: "center" });
    tb(s, r[2], { x: 7.8, y: y + 0.08, w: 4.8, h: rh - 0.16, fontFace: BODY, fontSize: 12.5, color: MUTE, margin: 0, valign: "center" });
  });
  notes.t7 = "Whole stack is free and runs offline. The headline addition over the plan: Capstone, so the disassembly and graph work on plain Windows — radare2/Ghidra stay the richer backend on the VM.";
  s.addNotes(notes.t7);
})();

// ============================================================ 8. GUI — BROWSER (screenshot)
(() => {
  const s = slide(PAPER);
  kicker(s, "The tool · 1", GREEN);
  title(s, "DLL browser — no more hunting for paths");
  s.addImage({ path: "shot_browser.png", x: 0.6, y: 1.75, w: 8.9, h: 5.29, sizing: { type: "contain", w: 8.9, h: 5.29 } });
  s.addShape(p.ShapeType.rect, { x: 0.6, y: 1.75, w: 8.9, h: 5.29, fill: { type: "none" }, line: { color: "C9D4E3", width: 1 } });
  const pt = (y, h, b) => { tb(s, h, { x: 9.75, y, w: 3.1, h: 0.35, fontFace: HEAD, fontSize: 14, bold: true, color: TXT, margin: 0 }); tb(s, b, { x: 9.75, y: y + 0.33, w: 3.1, h: 0.8, fontFace: BODY, fontSize: 12, color: MUTE, margin: 0, valign: "top" }); };
  pt(1.9, 0, "Running processes", "Pick a process → see every DLL it has loaded, with the full path on disk.");
  pt(3.15, 0, "Folder scan", "Or sweep System32 / any folder, with a live filter box.");
  pt(4.4, 0, "One-click analysis", "Triage, Exports, Imports run instantly — here, triage of cryptnet.dll.");
  pt(5.75, 0, "Enumerated via ctypes", "ToolHelp32 — zero dependencies beyond the standard library.");
  notes.t8 = "Demo 1. The process/DLL browser solves the real annoyance: finding the DLL. ToolHelp32 via ctypes lists loaded modules with paths. Shown: live triage of cryptnet.dll — arch, hashes, ASLR/DEP/CFG.";
  s.addNotes(notes.t8);
})();

// ============================================================ 9. GUI — GRAPH (screenshot) — HEADLINE
(() => {
  const s = slide(PAPER);
  kicker(s, "The tool · 2  — headline feature", GREEN);
  title(s, "IDA-style graph view, on Windows, no WSL");
  s.addImage({ path: "shot_graph.png", x: 0.6, y: 1.75, w: 8.9, h: 4.71, sizing: { type: "contain", w: 8.9, h: 4.71 } });
  s.addShape(p.ShapeType.rect, { x: 0.6, y: 1.75, w: 8.9, h: 4.71, fill: { type: "none" }, line: { color: "C9D4E3", width: 1 } });
  const pt = (y, h, c, b) => { tb(s, h, { x: 9.75, y, w: 3.1, h: 0.35, fontFace: HEAD, fontSize: 14, bold: true, color: c, margin: 0 }); tb(s, b, { x: 9.75, y: y + 0.33, w: 3.1, h: 0.85, fontFace: BODY, fontSize: 12, color: MUTE, margin: 0, valign: "top" }); };
  pt(1.9, 0, TXT, "Control-flow graph", "Basic blocks as boxes, recovered by recursive descent with Capstone.");
  pt(3.05, 0, GREEN, "IDA edge colours", "green = branch taken · red = fall-through · blue = unconditional.");
  pt(4.2, 0, BLUE, "Pseudo-C panel", "if / goto skeleton of the function; 'AI explain' fills in intent via Qwen.");
  block(s, 9.72, 5.45, 3.16, 1.5, null, null, { fill: INK, line: INK });
  tb(s, "Proven on bcryptPrimitives.dll &\ncryptnet.dll — 132 blocks / 215\nedges recovered, all four edge\ntypes, prologue correct.",
    { x: 9.9, y: 5.6, w: 2.85, h: 1.3, fontFace: BODY, fontSize: 11.5, color: "C7D3E3", margin: 0, valign: "top" });
  notes.t9 = "Demo 2, the headline. Real recursive-descent CFG recovery with Capstone — runs on plain Windows, no WSL. Screenshot is bcryptPrimitives.dll. Honest line: full C decompilation is Ghidra/Hex-Rays; I show the true branch skeleton and the LLM supplies intent.";
  s.addNotes(notes.t9);
})();

// ============================================================ 10. HALLUCINATION CONTROL
(() => {
  const s = slide(PAPER);
  kicker(s, "Trust the output", GREEN);
  title(s, "Hallucination control: the validator");
  tb(s, "A 7B model explains well with rich context and a strict format — and invents things without. Five guards keep it honest:",
    { x: 0.6, y: 1.72, w: 12.1, h: 0.6, fontFace: BODY, fontSize: 15, color: MUTE, margin: 0 });
  const g = [
    ["Name check", GREEN, "Every API the model names must appear in the block's asm or imports — else re-ask once, then mark 'unverified'."],
    ["JSON check", BLUE, "Output must parse to the fixed schema; Ollama's format=json makes failures rare, rejected ones retry."],
    ["Low temperature", GOLD, "0.1 keeps explanations stable and repeatable between runs."],
    ["Few-shot examples", BLUE, "2–3 hand-written examples from my own test DLLs noticeably lift small-model quality."],
    ["Chunking", GREEN, "Large functions are explained block-by-block, so nothing falls outside the context window."],
  ];
  g.forEach((c, i) => {
    const col = i % 2, rowi = (i - col) / 2;
    const x = 0.6 + col * 6.2, y = 2.5 + rowi * 1.25;
    block(s, x, y, 5.95, 1.1, null, null, { line: "D7E0EC" });
    s.addShape(p.ShapeType.ellipse, { x: x + 0.22, y: y + 0.32, w: 0.46, h: 0.46, fill: { color: c[1] } });
    tb(s, String(i + 1), { x: x + 0.22, y: y + 0.34, w: 0.46, h: 0.42, align: "center", fontFace: HEAD, fontSize: 16, bold: true, color: PAPER, margin: 0 });
    tb(s, c[0], { x: x + 0.85, y: y + 0.14, w: 4.9, h: 0.35, fontFace: HEAD, fontSize: 15, bold: true, color: c[1], margin: 0 });
    tb(s, c[2], { x: x + 0.85, y: y + 0.47, w: 4.95, h: 0.6, fontFace: BODY, fontSize: 11.8, color: MUTE, margin: 0, valign: "top" });
  });
  block(s, 6.8, 3.75, 5.95, 2.35, null, null, { fill: INK, line: INK });
  tb(s, "Guarantee", { x: 7.05, y: 3.9, w: 5, h: 0.35, fontFace: MONO, fontSize: 12, bold: true, color: GREEN, margin: 0 });
  tb(s, "The model may never state an API, constant or address that the tools did not observe. If it does, the claim is downgraded — never shown as fact.",
    { x: 7.05, y: 4.3, w: 5.5, h: 1.7, fontFace: HEAD, fontSize: 16, italic: true, color: PAPER, margin: 0, valign: "top" });
  notes.t10 = "This is what makes the output trustworthy. The name check is pure Python and unit-tested. Emphasise: an invented API is caught automatically and flagged, not presented as truth.";
  s.addNotes(notes.t10);
})();

// ============================================================ 11. PART 2 — REA AGENT + MCP
(() => {
  const s = slide(INK);
  kicker(s, "System architecture · Part 2", "7FB4FF");
  tb(s, "REA-style agent over an MCP server", { x: 0.6, y: 0.82, w: 12, h: 0.8, fontFace: HEAD, fontSize: 30, bold: true, color: PAPER, margin: 0 });
  tb(s, "Ask a question; the model picks which analysis tool to call next, reads the result, and loops until it can answer with evidence.",
    { x: 0.6, y: 1.65, w: 12.1, h: 0.6, fontFace: BODY, fontSize: 14, color: "9FC6F0", margin: 0 });
  block(s, 0.6, 2.5, 2.7, 1.3, "Your question", "\"Does it touch the network? Where?\"", { fill: INK2, line: "33465F", tc: "7FB4FF", bc: "C7D3E3", bs: 11 });
  block(s, 4.0, 2.5, 2.7, 1.3, "Agent loop", "Qwen picks the next\ntool · max 15 steps", { fill: GOLD, line: GOLD, tc: "2A1E00", bc: "2A1E00", bs: 11 });
  block(s, 7.4, 2.5, 2.7, 1.3, "MCP server", "11 read-only tools\n(also for Claude Code)", { fill: INK2, line: "33465F", tc: "7FB4FF", bc: "C7D3E3", bs: 11 });
  block(s, 10.05, 4.3, 2.7, 1.3, "4 backends", "pefile · radare2\ncapa/FLOSS · dnfile", { fill: INK2, line: "33465F", tc: "7FB4FF", bc: "C7D3E3", bs: 11 });
  block(s, 4.0, 4.3, 2.7, 1.3, "Evidence log", "every call → E1, E2…\nin SQLite", { fill: GREEN, line: GREEN, tc: "06321C", bc: "063018", bs: 11 });
  block(s, 0.6, 4.3, 2.7, 1.3, "Report", "observed · inferred ·\nunknown  + graphs", { fill: INK2, line: "33465F", tc: "7FB4FF", bc: "C7D3E3", bs: 11 });
  arrow(s, 3.3, 3.15, 4.0, 3.15, "6E86A6");
  arrow(s, 6.7, 3.15, 7.4, 3.15, "6E86A6");
  arrow(s, 8.75, 3.8, 10.4, 4.3, "6E86A6");
  arrow(s, 5.35, 3.8, 5.35, 4.3, GREEN);
  arrow(s, 4.0, 4.95, 3.3, 4.95, "6E86A6");
  tb(s, "Same tools, two front-ends: my local Qwen agent for the offline demo, and Claude Code over MCP as a strong-model upper-bound reference.",
    { x: 0.6, y: 6.15, w: 12.1, h: 0.7, fontFace: BODY, fontSize: 13.5, italic: true, color: "C7D3E3", margin: 0 });
  notes.t11 = "Part 2 turns the fixed pipeline into an agent, exactly the REA idea. The model plans; the tools observe; the evidence log records every call. The same MCP server can be driven by Claude Code to measure how far the local model is from a frontier model.";
  s.addNotes(notes.t11);
})();

// ============================================================ 12. EVIDENCE MODEL
(() => {
  const s = slide(PAPER);
  kicker(s, "What separates it from a chatbot", GREEN);
  title(s, "Every statement carries a label");
  const cards = [
    ["OBSERVED", GREEN, "C7E3D0", "Read directly from the binary by a tool.", "\"imports RegSetValueExW [E3]\""],
    ["INFERRED", GOLD, "F6E3C2", "The model's reading of observed facts.", "\"likely writes a config value [E3,E7]\""],
    ["UNKNOWN", MUTE, "DCE2EA", "Asked but not answerable statically.", "\"which registry hive at runtime\""],
  ];
  cards.forEach((c, i) => {
    const x = 0.6 + i * 4.15;
    block(s, x, 1.95, 3.85, 2.9, null, null, { line: c[2] });
    s.addShape(p.ShapeType.roundRect, { x: x + 0.3, y: 2.2, w: 2.7, h: 0.55, rectRadius: 0.05, fill: { color: c[1] } });
    tb(s, c[0], { x: x + 0.3, y: 2.29, w: 2.7, h: 0.4, align: "center", fontFace: MONO, fontSize: 14, bold: true, color: i === 2 ? PAPER : "0B2316", margin: 0 });
    tb(s, c[3], { x: x + 0.3, y: 3.0, w: 3.3, h: 0.9, fontFace: BODY, fontSize: 13.5, color: TXT, margin: 0, valign: "top" });
    s.addShape(p.ShapeType.rect, { x: x + 0.3, y: 3.95, w: 3.3, h: 0.72, fill: { color: PANEL }, line: { color: c[2] } });
    tb(s, c[4], { x: x + 0.42, y: 4.02, w: 3.1, h: 0.6, fontFace: MONO, fontSize: 10.5, italic: true, color: MUTE, margin: 0, valign: "center" });
  });
  block(s, 0.6, 5.1, 12.15, 1.35, null, null, { fill: INK, line: INK });
  tb(s, "Validator", { x: 0.9, y: 5.26, w: 3, h: 0.35, fontFace: MONO, fontSize: 12, bold: true, color: GREEN, margin: 0 });
  tb(s, "Before the report is written, every cited E-id must exist and every API/address in an 'observed' line must appear in that evidence. Statements that fail are downgraded to 'inferred' or dropped.",
    { x: 0.9, y: 5.62, w: 11.6, h: 0.8, fontFace: BODY, fontSize: 14.5, color: "DCE6F2", margin: 0, valign: "top" });
  notes.t12 = "The evidence model is the spine. Observed/inferred/unknown with citations, and a validator that mechanically downgrades any 'observed' claim it can't back up. This is unit-tested and runs with no backend.";
  s.addNotes(notes.t12);
})();

// ============================================================ 13. EVALUATION
(() => {
  const s = slide(PAPER);
  kicker(s, "How I measure it", GREEN);
  title(s, "Evaluation on DLLs I compiled myself");
  tb(s, "When you compile the test DLLs, the C source is the answer key for every explanation — so accuracy is gradable.",
    { x: 0.6, y: 1.7, w: 12.1, h: 0.55, fontFace: BODY, fontSize: 14.5, color: MUTE, margin: 0 });
  block(s, 0.6, 2.45, 5.9, 2.5, null, null, { line: "D7E0EC" });
  tb(s, "Metrics", { x: 0.85, y: 2.6, w: 5, h: 0.35, fontFace: HEAD, fontSize: 16, bold: true, color: GREEN, margin: 0 });
  tb(s, ["Purpose accuracy (1–5 vs source)", "Name-check pass rate", "Function-name guess on stripped DLLs", "Evidence validity & false 'observed' rate", "Tool calls and seconds per question"].map(t => ({ text: t, options: { bullet: { indent: 14 }, breakLine: true, paraSpaceAfter: 7 } })),
    { x: 0.85, y: 3.05, w: 5.4, h: 1.85, fontFace: BODY, fontSize: 13, color: TXT, margin: 0, valign: "top" });
  block(s, 6.85, 2.45, 5.9, 2.5, null, null, { line: "D7E0EC" });
  tb(s, "Experiments", { x: 7.1, y: 2.6, w: 5, h: 0.35, fontFace: HEAD, fontSize: 16, bold: true, color: BLUE, margin: 0 });
  tb(s, ["Qwen 7B vs 14B as planner", "With vs without pseudo-C in the prompt", "-O0 vs -O2 (optimised is harder)", "Text input vs screenshot (Qwen-VL)", "Local model vs Claude Code over MCP"].map(t => ({ text: t, options: { bullet: { indent: 14 }, breakLine: true, paraSpaceAfter: 7 } })),
    { x: 7.1, y: 3.05, w: 5.4, h: 1.85, fontFace: BODY, fontSize: 13, color: TXT, margin: 0, valign: "top" });
  block(s, 0.6, 5.1, 12.15, 1.35, null, null, { fill: PANEL, line: "D7E0EC" });
  tb(s, "Test set", { x: 0.9, y: 5.25, w: 3, h: 0.35, fontFace: HEAD, fontSize: 15, bold: true, color: TXT, margin: 0 });
  tb(s, "~15–20 C functions (array sum, string ops, XOR cipher, checksum, state machine, recursion, a registry-writing WinAPI call) × 4 builds each: -O0 / -O2 × with / without symbols.",
    { x: 0.9, y: 5.62, w: 11.6, h: 0.8, fontFace: BODY, fontSize: 13.5, color: MUTE, margin: 0, valign: "top" });
  notes.t13 = "Rigorous eval because I own the ground truth. Four variants per function stress the model on optimisation and stripping. The results table from the four experiments is the strongest part of the written report.";
  s.addNotes(notes.t13);
})();

// ============================================================ 14. STATUS / RESULTS
(() => {
  const s = slide(INK);
  kicker(s, "Where it stands today", GREEN);
  tb(s, "Working now", { x: 0.6, y: 0.82, w: 12, h: 0.8, fontFace: HEAD, fontSize: 32, bold: true, color: PAPER, margin: 0 });
  const stat = (x, big, small, c) => {
    block(s, x, 1.9, 3.85, 1.7, null, null, { fill: INK2, line: "33465F" });
    tb(s, big, { x: x + 0.2, y: 2.05, w: 3.5, h: 0.85, fontFace: HEAD, fontSize: 40, bold: true, color: c, margin: 0 });
    tb(s, small, { x: x + 0.2, y: 2.95, w: 3.5, h: 0.6, fontFace: BODY, fontSize: 12.5, color: "C7D3E3", margin: 0, valign: "top" });
  };
  stat(0.6, "132 / 215", "blocks / edges recovered on cryptnet.dll (Capstone)", GREEN);
  stat(4.75, "11", "read-only MCP analysis tools, shared by both front-ends", "7FB4FF");
  stat(8.9, "100%", "offline — no data leaves the machine", GOLD);
  const done = [
    "Static triage, exports & imports — tested on Windows",
    "Windows-native CFG graph view (Capstone) — no WSL",
    "Process / DLL browser GUI with one-click analysis",
    "Evidence log, labels & report validator — unit-tested",
    "MCP server + local Qwen agent loop — wired end to end",
  ];
  block(s, 0.6, 3.9, 12.15, 2.4, null, null, { fill: "0C1826", line: "2A3C55" });
  tb(s, "Shipped components", { x: 0.9, y: 4.05, w: 6, h: 0.4, fontFace: HEAD, fontSize: 16, bold: true, color: PAPER, margin: 0 });
  tb(s, done.map(t => ({ text: t, options: { bullet: { code: "2713", indent: 18 }, breakLine: true, paraSpaceAfter: 8, color: "DCE6F2" } })),
    { x: 0.9, y: 4.55, w: 11.5, h: 1.7, fontFace: BODY, fontSize: 14, color: "DCE6F2", margin: 0, valign: "top" });
  notes.t14 = "Concrete results. The 132/215 number is a real run against a Windows system DLL. Everything in the static + native-graph + evidence path works today; the radare2/Ollama-heavy stages run on the VM.";
  s.addNotes(notes.t14);
})();

// ============================================================ 15. LIMITATIONS & ETHICS
(() => {
  const s = slide(PAPER);
  kicker(s, "Honesty", GOLD);
  title(s, "Limitations & ethics");
  const lim = [
    ["Optimised code is hard", "Small models still slip on -O2; the name check catches invented APIs, not every wrong explanation."],
    ["Scale", "Large DLLs have thousands of functions — explain exports first, cache everything, let the user pick the rest."],
    ["Not a decompiler", "The C panel is a CFG skeleton + LLM intent, not Ghidra/Hex-Rays output."],
    ["Packed binaries", "VMProtect / Themida are out of scope by design."],
  ];
  lim.forEach((c, i) => {
    const col = i % 2, rowi = (i - col) / 2;
    const x = 0.6 + col * 6.2, y = 1.95 + rowi * 1.3;
    block(s, x, y, 5.95, 1.15, null, null, { line: "D7E0EC" });
    tb(s, c[0], { x: x + 0.25, y: y + 0.15, w: 5.5, h: 0.4, fontFace: HEAD, fontSize: 15, bold: true, color: TXT, margin: 0 });
    tb(s, c[1], { x: x + 0.25, y: y + 0.52, w: 5.5, h: 0.58, fontFace: BODY, fontSize: 12.5, color: MUTE, margin: 0, valign: "top" });
  });
  block(s, 0.6, 4.7, 12.15, 1.75, null, null, { fill: INK, line: INK });
  s.addShape(p.ShapeType.roundRect, { x: 0.9, y: 4.95, w: 1.6, h: 0.5, rectRadius: 0.05, fill: { color: GREEN } });
  tb(s, "ETHICS", { x: 0.9, y: 5.03, w: 1.6, h: 0.35, align: "center", fontFace: MONO, fontSize: 13, bold: true, color: "06321C", margin: 0 });
  tb(s, "Analyse only DLLs you compiled yourself, open-source libraries, or software whose licence permits reverse engineering — many commercial EULAs forbid it. The tool is strictly read-only and never executes the binary. This is stated in the report; examiners look for it.",
    { x: 0.9, y: 5.55, w: 11.6, h: 0.85, fontFace: BODY, fontSize: 14, color: "DCE6F2", margin: 0, valign: "top" });
  notes.t15 = "Stating limits and ethics earns marks and is just correct. Key ethical line: only your own / open-source / licensed binaries, and the tool never runs the target.";
  s.addNotes(notes.t15);
})();

// ============================================================ 16. ROADMAP + CLOSE
(() => {
  const s = slide(INK);
  kicker(s, "What's next", GREEN);
  tb(s, "Roadmap & links", { x: 0.6, y: 0.82, w: 12, h: 0.8, fontFace: HEAD, fontSize: 32, bold: true, color: PAPER, margin: 0 });
  const road = [
    ["Fine-tune", "LoRA on (assembly, C) pairs — referencing the LLM4Decompile project."],
    ["ARM64", "radare2 already handles it; only the prompts change."],
    ["Xref navigation", "Double-click a call/jmp target to jump to that function."],
    ["Decompiler integration", "Wire Ghidra headless for true pseudo-C alongside the skeleton."],
  ];
  road.forEach((c, i) => {
    const x = 0.6 + (i % 2) * 6.2, y = 1.9 + Math.floor(i / 2) * 1.2;
    block(s, x, y, 5.95, 1.05, null, null, { fill: INK2, line: "33465F" });
    s.addShape(p.ShapeType.ellipse, { x: x + 0.22, y: y + 0.3, w: 0.46, h: 0.46, fill: { color: GREEN } });
    tb(s, String(i + 1), { x: x + 0.22, y: y + 0.32, w: 0.46, h: 0.42, align: "center", fontFace: HEAD, fontSize: 16, bold: true, color: "06321C", margin: 0 });
    tb(s, c[0], { x: x + 0.85, y: y + 0.12, w: 4.9, h: 0.35, fontFace: HEAD, fontSize: 14.5, bold: true, color: PAPER, margin: 0 });
    tb(s, c[1], { x: x + 0.85, y: y + 0.46, w: 4.95, h: 0.55, fontFace: BODY, fontSize: 11.8, color: "C7D3E3", margin: 0, valign: "top" });
  });
  block(s, 0.6, 4.55, 12.15, 2.1, null, null, { fill: "0C1826", line: GREEN });
  tb(s, "Source code & repository", { x: 0.95, y: 4.75, w: 8, h: 0.4, fontFace: HEAD, fontSize: 18, bold: true, color: PAPER, margin: 0 });
  tb(s, "github.com/Sumit-2004/RE_Assembler", { x: 0.95, y: 5.3, w: 11, h: 0.5, fontFace: MONO, fontSize: 18, bold: true, color: GREEN, margin: 0 });
  tb(s, "Full Python source, the Tkinter GUI, the MCP server, test DLLs and this deck are in the repo.   ·   Thank you.",
    { x: 0.95, y: 5.95, w: 11.5, h: 0.5, fontFace: BODY, fontSize: 13.5, italic: true, color: "9FB0C3", margin: 0 });
  notes.t16 = "Close on momentum and the deliverables: source, GitHub, test DLLs, slides. Fill in the repo URL and your username. Stretch goals show you know where it goes next (LoRA/LLM4Decompile, ARM64, xrefs, real decompiler).";
  s.addNotes(notes.t16);
})();

p.writeFile({ fileName: "AI_Assembly_Explainer.pptx" }).then(f => console.log("WROTE", f));
