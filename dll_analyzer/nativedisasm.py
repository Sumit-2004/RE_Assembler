"""Windows-native disassembly and CFG recovery with Capstone (no WSL needed).

Capstone is a pure-Python-installable disassembler, so this gives a real
IDA-style view -- functions, basic blocks, control-flow edges -- on plain
Windows with only `pip install capstone pefile`. radare2/Ghidra are not required
for this path; they stay the richer backend on the Linux VM.

Recovery is recursive-descent: linearly decode a window from the entry, then
keep only the blocks reachable by following jumps and fall-throughs. Indirect
jumps (jump tables) end a block with no recovered successor, exactly as they do
in any first-pass disassembler.
"""
from . import backends, tools

_CAP_HINT = "pip install capstone"
WINDOW = 0x4000  # bytes to decode from a function entry (16 KiB is plenty per function)

# IDA-style edge kinds -> colours, matching render.py.
EDGE_COLORS = {"uncond": "#2667c7", "jump": "#1a9a4a", "fail": "#c0392b", "fall": "#888"}


def _mode(machine: int):
    cap = backends.require("capstone", _CAP_HINT)
    if machine == 0x8664:
        return cap.Cs(cap.CS_ARCH_X86, cap.CS_MODE_64), 64
    if machine == 0x014C:
        return cap.Cs(cap.CS_ARCH_X86, cap.CS_MODE_32), 32
    raise backends.BackendMissing(
        f"this native view handles x86/x64 only (machine {hex(machine)}); "
        "use the radare2 backend on the VM for other architectures")


def _imm_target(insn):
    cap = backends.require("capstone", _CAP_HINT)
    for op in insn.operands:
        if op.type == cap.x86.X86_OP_IMM:
            return op.value.imm
    return None


def disassemble_function(path: str, address: str, window: int = WINDOW) -> dict:
    """Recover one function's basic blocks and CFG edges from the entry address.

    Args:
        path: absolute path to the DLL/EXE
        address: entry address as a hex string (an export address works)

    Returns {name, addr, arch, blocks:[...], edges:[...]} where each block has
    its instructions, resolved call mnemonics, and jump/fail successor addresses.
    """
    cap = backends.require("capstone", _CAP_HINT)
    pe = tools._open(path)
    base = pe.OPTIONAL_HEADER.ImageBase
    md, bits = _mode(pe.FILE_HEADER.Machine)
    md.detail = True

    start = int(address, 16)
    rva = start - base
    mapped = pe.get_memory_mapped_image()
    code = mapped[rva:rva + window]

    # 1. linear decode the window into an address-keyed map
    insns: dict[int, object] = {}
    order: list[int] = []
    for insn in md.disasm(code, start):
        insns[insn.address] = insn
        order.append(insn.address)
    pe.close()
    if not order:
        return {"name": "", "addr": address, "arch": f"x{bits}", "blocks": [], "edges": []}

    def is_jump(i):
        return i.group(cap.CS_GRP_JUMP)

    def is_ret(i):
        return i.group(cap.CS_GRP_RET) or i.mnemonic in ("ret", "retn", "retf", "iret")

    last = order[-1]

    # 2. leaders: entry, every branch target in range, every insn after a branch/ret
    leaders = {start}
    for addr in order:
        i = insns[addr]
        nxt = addr + i.size
        if is_jump(i) or is_ret(i):
            if nxt in insns:
                leaders.add(nxt)
            tgt = _imm_target(i) if is_jump(i) else None
            if tgt in insns:
                leaders.add(tgt)

    # 3. carve blocks between leaders
    blocks: dict[int, dict] = {}
    cur = None
    for addr in order:
        if addr in leaders:
            cur = {"addr": hex(addr), "_start": addr, "asm": [], "calls": [],
                   "jump": None, "fail": None, "kind": None}
            blocks[addr] = cur
        i = insns[addr]
        cur["asm"].append(f"{i.mnemonic} {i.op_str}".strip())
        if i.group(cap.CS_GRP_CALL):
            cur["calls"].append(f"call {i.op_str}")
        nxt = i.address + i.size
        # a block ends at a jump, a ret, or right before the next leader
        ends = is_jump(i) or is_ret(i) or (nxt in leaders)
        if ends:
            if is_ret(i):
                pass  # no successors
            elif is_jump(i):
                tgt = _imm_target(i)
                if i.mnemonic == "jmp":
                    cur["jump"] = hex(tgt) if tgt in insns else None
                    cur["kind"] = "uncond"
                else:  # conditional: taken target + fall-through
                    cur["jump"] = hex(tgt) if tgt in insns else None
                    cur["fail"] = hex(nxt) if nxt in insns else None
                    cur["kind"] = "cond"
            else:  # plain fall-through into the next block
                cur["fail"] = hex(nxt) if nxt in insns else None
                cur["kind"] = "fall"
            cur = None  # force a new block at the next leader

    # 4. keep only blocks reachable from the entry
    reachable, stack = set(), [start]
    while stack:
        a = stack.pop()
        if a in reachable or a not in blocks:
            continue
        reachable.add(a)
        b = blocks[a]
        for succ in (b["jump"], b["fail"]):
            if succ:
                stack.append(int(succ, 16))

    kept = [blocks[a] for a in order if a in reachable and a in blocks]
    edges = []
    for b in kept:
        if b["jump"]:
            edges.append({"src": b["addr"], "dst": b["jump"],
                          "kind": "uncond" if b["kind"] == "uncond" else "jump"})
        if b["fail"]:
            edges.append({"src": b["addr"], "dst": b["fail"],
                          "kind": "fail" if b["kind"] == "cond" else "fall"})
    for b in kept:
        b.pop("_start", None)
    return {"name": _name_for(path, start), "addr": address, "arch": f"x{bits}",
            "blocks": kept, "edges": edges}


def _name_for(path: str, va: int) -> str:
    for e in tools.list_exports(path):
        if int(e["address"], 16) == va:
            return e["name"]
    return f"sub_{va:x}"


def list_code_functions(path: str) -> list[dict]:
    """Entry points to disassemble: exported functions first, then the entry point."""
    funcs = [{"name": e["name"], "addr": e["address"]}
             for e in tools.list_exports(path) if not e.get("forwarder")]
    triage = tools.triage_dll(path)
    ep = triage.get("entry_point")
    if ep and all(f["addr"] != ep for f in funcs):
        funcs.insert(0, {"name": "entry_point", "addr": ep})
    return funcs


def pseudo_skeleton(func: dict) -> str:
    """A C-ish control-flow skeleton from the CFG (honest: not a decompilation).

    IDA/Ghidra run a full decompiler for real C; without that engine this shows
    the branch structure as labelled blocks and gotos, which is still the shape
    of the function. The AI explainer (Qwen) fills in intent when Ollama is up.
    """
    lines = [f"/* {func['name']}  —  control-flow skeleton reconstructed from the CFG.",
             "   Not a full decompilation; run 'AI explain' for reconstructed intent. */",
             f"void {func['name']}(void)", "{"]
    for b in func["blocks"]:
        lines.append(f"{b['addr'].replace('0x', 'loc_')}:")
        for ins in b["asm"][:-1]:
            lines.append(f"    // {ins}")
        term = b["asm"][-1] if b["asm"] else ""
        if b["kind"] == "cond":
            lines.append(f"    if ({term}) goto {(b['jump'] or '?').replace('0x', 'loc_')};")
            if b["fail"]:
                lines.append(f"    goto {b['fail'].replace('0x', 'loc_')};")
        elif b["kind"] == "uncond" and b["jump"]:
            lines.append(f"    // {term}")
            lines.append(f"    goto {b['jump'].replace('0x', 'loc_')};")
        elif b["fail"]:
            lines.append(f"    // {term}")
            lines.append(f"    goto {b['fail'].replace('0x', 'loc_')};")
        else:
            lines.append(f"    // {term}")
            lines.append("    return;")
    lines.append("}")
    return "\n".join(lines)
