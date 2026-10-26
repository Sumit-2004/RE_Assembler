"""Explain assembly in plain English with a local Qwen model (Part 1, Phase 3).

The model's only job is to explain facts the disassembler already produced. It
is fed rich context (arch, calling convention, resolved calls, strings, pseudo-C
and the block's assembly) and must answer in a strict JSON shape. Two guards
fight hallucination: a JSON check (Ollama's format="json" makes failures rare)
and a name check that rejects any API the model names that does not appear in
the block's own assembly or imports.

The name check (``verify_names``) is pure Python and has no backend dependency,
so it is unit-tested on any platform. Only ``ask`` needs Ollama running.
"""
import json
import re

from . import backends

MODEL = "qwen2.5-coder:7b"
NUM_CTX = 16384  # Ollama's default context is tiny; long functions get cut off otherwise.

SYSTEM_PROMPT = """You explain x86/x64 assembly to a computer-science student.
Use ONLY the facts given. If something is unclear, say "unknown".
Never name an API, constant or variable that does not appear in the input.
Reply as JSON:
{"summary": "one line, plain English",
 "detail": "2-4 sentences: what the block computes and why",
 "instructions": [{"asm": "...", "meaning": "..."}],
 "branch": "what decides which way the block exits, or null",
 "confidence": "high | medium | low"}"""

# x64 Windows calling convention, handed to the model so it reads args correctly.
_CONVENTION = ("x64 Windows calling convention: integer/pointer arguments in "
               "RCX, RDX, R8, R9 (then the stack); return value in RAX.")

# Token that looks like an API / identifier the model might cite.
_IDENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:[AW])?)\b")
# Words we never treat as an "invented API" even if absent from the asm.
_STOPWORDS = frozenset({
    "the", "a", "an", "and", "or", "to", "of", "in", "is", "it", "this", "that",
    "value", "register", "function", "block", "returns", "return", "unknown",
    "stack", "pointer", "argument", "arguments", "jump", "branch", "call", "calls",
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10",
    "r11", "r12", "r13", "r14", "r15", "eax", "ebx", "ecx", "edx", "null", "true",
    "false", "high", "medium", "low", "if", "else", "then", "into", "from", "with",
})


def build_block_prompt(block: dict, func_name: str, exported: bool,
                       imports: list[str], strings: list[str], pseudo_c: str,
                       arch: str = "x64") -> str:
    """Assemble the rich per-block user prompt the plan prescribes."""
    lines = [
        f"Architecture: {arch}. {_CONVENTION if arch == 'x64' else ''}".strip(),
        f"Function: {func_name} ({'exported' if exported else 'internal'}).",
    ]
    calls = block.get("calls") or []
    if calls:
        lines.append("Calls / APIs referenced in this block:\n  " + "\n  ".join(calls))
    if imports:
        lines.append("Imported APIs available: " + ", ".join(sorted(set(imports))[:40]))
    if strings:
        lines.append("Strings referenced: " + " | ".join(strings[:20]))
    if pseudo_c:
        lines.append("Decompiled pseudo-C of the whole function (context):\n" + pseudo_c[:4000])
    lines.append("Assembly of THIS block, one instruction per line:\n" + "\n".join(block.get("asm", [])))
    return "\n\n".join(lines)


def verify_names(answer: dict, allowed_text: str) -> tuple[bool, list[str]]:
    """Name check: every API-like identifier the model cites must appear in input.

    Returns (ok, offenders). ``allowed_text`` is the block's assembly plus the
    list of imported API names -- the only place a real API name can come from.
    """
    haystack = allowed_text.lower()
    mentioned = " ".join([
        answer.get("summary", ""),
        answer.get("detail", ""),
        " ".join(i.get("meaning", "") for i in answer.get("instructions", [])),
    ])
    offenders = []
    for token in _IDENT.findall(mentioned):
        low = token.lower()
        if low in _STOPWORDS or len(token) < 4:
            continue
        # Only flag CamelCase / API-shaped identifiers, not ordinary English words.
        looks_like_api = any(c.isupper() for c in token[1:]) or token.endswith(("A", "W"))
        if looks_like_api and low not in haystack:
            offenders.append(token)
    return (not offenders), sorted(set(offenders))


def ask(user: str, system: str = SYSTEM_PROMPT, model: str = MODEL) -> dict:
    """Send one chat request to Ollama and parse the JSON answer.

    Needs Ollama running locally with the model pulled. Low temperature keeps
    explanations consistent between runs.
    """
    ollama = backends.require(
        "ollama", "install Ollama (ollama.com/install.sh), run 'ollama pull "
        f"{model}', then pip install ollama")
    r = ollama.chat(
        model=model,
        messages=[{"role": "system", "content": system},
                  {"role": "user", "content": user}],
        format="json",
        options={"temperature": 0.1, "num_ctx": NUM_CTX},
    )
    return json.loads(r["message"]["content"])


def explain_block(block: dict, func_name: str, exported: bool, imports: list[str],
                  strings: list[str], pseudo_c: str, arch: str = "x64") -> dict:
    """Explain one basic block, then run the name check and re-ask once on failure."""
    allowed = "\n".join(block.get("asm", [])) + "\n" + "\n".join(imports)
    prompt = build_block_prompt(block, func_name, exported, imports, strings, pseudo_c, arch)
    answer = ask(prompt)
    ok, offenders = verify_names(answer, allowed)
    if not ok:
        # Re-ask once, pointing out the mismatch, then mark it if still wrong.
        retry = prompt + ("\n\nThese names are NOT in the input and must not appear: "
                          + ", ".join(offenders) + ". Correct your answer.")
        answer = ask(retry)
        ok, offenders = verify_names(answer, allowed)
        if not ok:
            answer["unverified"] = offenders
    answer["addr"] = block.get("addr")
    return answer


def explain_function(func: dict, imports: list[str], block_notes: dict,
                     exported: bool = False) -> dict:
    """Summarise a whole function from its block notes plus pseudo-C."""
    notes = "\n".join(f"{addr}: {n.get('summary', '')}" for addr, n in block_notes.items())
    prompt = (f"Function {func['name']} ({'exported' if exported else 'internal'}).\n"
              f"Block summaries:\n{notes}\n\nDecompiled pseudo-C:\n{func.get('pseudo_c', '')[:4000]}\n\n"
              "Give the JSON shape, where 'summary' is what the whole function does.")
    return ask(prompt)


def explain_dll(func_summaries: dict[str, str]) -> dict:
    """One whole-DLL overview from the per-function summaries."""
    body = "\n".join(f"{name}: {summ}" for name, summ in func_summaries.items())
    prompt = ("These are the function summaries of a DLL:\n" + body +
              "\n\nGive the JSON shape; 'summary' is what the whole DLL is for.")
    return ask(prompt)
