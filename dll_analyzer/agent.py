"""The local Qwen agent loop (Part 2, Week 6).

You ask a question; the planner model picks a tool, reads its JSON result, and
calls more tools until it can answer with evidence. The model never guesses
facts about the binary -- it only reasons over tool outputs. Every call is
written to the evidence log, and the system prompt asks the model to cite the
E-ids in its final answer.

Needs Ollama for the planner model; the tools themselves need their own
backends (radare2, capa, ...) only when the model actually calls them.
"""
import json

from . import backends, disasm
from .evidence import EvidenceLog
from .registry import BY_NAME, TOOLS

PLANNER_MODEL = "qwen2.5:14b"  # general model plans; qwen2.5-coder explains assembly
NUM_CTX = 32768
MAX_STEPS = 15
RESULT_CLIP = 8000  # paging in the tools is the real fix; this just stops overflow

SYSTEM = (
    "You analyse Windows DLLs with tools. Gather facts by calling tools; never "
    "guess. Cite the evidence id (E1, E2, ...) printed after each tool result. "
    "Finish with three labelled sections: OBSERVED (each citing a tool and "
    "address/E-id), INFERRED (your reading of observed facts), UNKNOWN (asked "
    "but not answerable from static analysis)."
)


def run(question: str, path: str, max_steps: int = MAX_STEPS,
        db_path: str = ":memory:") -> dict:
    """Answer ``question`` about the DLL at ``path`` with a tool-using agent.

    Returns {"answer": str, "steps": int, "evidence": [...]} and keeps the full
    tool-call log in SQLite at ``db_path``.
    """
    ollama = backends.require("ollama", "install Ollama and 'ollama pull qwen2.5:14b'")
    log = EvidenceLog(db_path, sha256=disasm._sha256(path))
    msgs = [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"DLL: {path}\nQuestion: {question}"}]

    for step in range(max_steps):
        r = ollama.chat(model=PLANNER_MODEL, messages=msgs, tools=TOOLS,
                        options={"temperature": 0.1, "num_ctx": NUM_CTX})
        msgs.append(r.message)
        if not r.message.tool_calls:
            return {"answer": r.message.content, "steps": step + 1, "evidence": log.all()}
        for call in r.message.tool_calls:
            name = call.function.name
            args = call.function.arguments
            try:
                result = BY_NAME[name](**args)
            except Exception as exc:  # feed the error back so the model can recover
                result = {"error": str(exc)}
            eid = log.record(name, args, result)
            payload = json.dumps(result, default=str)[:RESULT_CLIP]
            msgs.append({"role": "tool", "tool_name": name,
                         "content": f"[{eid}] {payload}"})

    return {"answer": "Stopped: step limit reached.", "steps": max_steps, "evidence": log.all()}
