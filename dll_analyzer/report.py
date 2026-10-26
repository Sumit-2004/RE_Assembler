"""Build the evidence-labelled report (Part 2).

Every statement is one of three labels:
    observed  -- read directly from the binary by a tool, cites evidence IDs
    inferred  -- the model's interpretation of observed facts, cites IDs
    unknown   -- asked but not answerable statically (no citation)

Before anything is written, ``validate`` checks that every cited evidence ID
exists and that every API/address named in an *observed* statement actually
appears in that evidence's result. Observed statements that fail are downgraded
to inferred. The output is HTML or Markdown with the six-section layout from the
plan and a full tool-call appendix.

Pure stdlib, so it is unit-tested without any backend.
"""
import html
import re
from dataclasses import dataclass, field

from .evidence import EvidenceLog

OBSERVED, INFERRED, UNKNOWN = "observed", "inferred", "unknown"
# Names worth checking in an observed claim: APIs, addresses, mangled symbols.
_CITED_TOKEN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*[AW]?|0x[0-9A-Fa-f]+)\b")


@dataclass
class Statement:
    label: str                       # observed | inferred | unknown
    text: str
    evidence: list[str] = field(default_factory=list)   # ["E3", "E7"]


def validate(statements: list[Statement], log: EvidenceLog) -> list[Statement]:
    """Drop dangling citations and downgrade unsupported 'observed' claims."""
    cleaned = []
    for st in statements:
        evidence = [e for e in st.evidence if log.exists(e)]
        label = st.label
        if label == OBSERVED:
            # Every API/address named must appear in at least one cited result.
            for token in _CITED_TOKEN.findall(st.text):
                if token.lower() in ("the", "and", "this", "that", "with", "imports"):
                    continue
                looks_cited = token.startswith("0x") or any(c.isupper() for c in token[1:])
                if looks_cited and not any(log.supports(e, token) for e in evidence):
                    label = INFERRED  # could not back it up -> downgrade
                    break
        cleaned.append(Statement(label, st.text, evidence))
    return cleaned


def _cite(st: Statement) -> str:
    return f" [{', '.join(st.evidence)}]" if st.evidence else ""


def to_markdown(question: str, answer: str, triage: dict, statements: list[Statement],
                log: EvidenceLog) -> str:
    by = {OBSERVED: [], INFERRED: [], UNKNOWN: []}
    for st in statements:
        by[st.label].append(st)
    out = ["# DLL Analysis Report", "",
           f"**Question:** {question}", "",
           "## 1. Summary", "", answer, "",
           "## 2. Triage", ""]
    for k in ("arch", "runtime", "aslr", "dep", "control_flow_guard", "sha256", "packer_hints"):
        if k in triage:
            out.append(f"- **{k}**: {triage[k]}")
    out += ["", "## 3. Observed facts", ""]
    out += [f"- {st.text}{_cite(st)}" for st in by[OBSERVED]] or ["- (none)"]
    out += ["", "## 4. Inferences", ""]
    out += [f"- {st.text}{_cite(st)}" for st in by[INFERRED]] or ["- (none)"]
    out += ["", "## 5. Unknowns and limitations", ""]
    out += [f"- {st.text}" for st in by[UNKNOWN]] or ["- (none)"]
    out += ["", "## 6. Evidence appendix", ""]
    for e in log.all():
        out.append(f"- **{e['eid']}** `{e['tool']}({e['args']})`")
    return "\n".join(out)


def to_html(question: str, answer: str, triage: dict, statements: list[Statement],
            log: EvidenceLog) -> str:
    esc = html.escape
    rows = "".join(
        f"<tr><td>{esc(str(k))}</td><td>{esc(str(v))}</td></tr>"
        for k, v in triage.items() if not isinstance(v, (list, dict)))

    def items(label):
        got = [f"<li>{esc(st.text)}{esc(_cite(st))}</li>" for st in statements if st.label == label]
        return "".join(got) or "<li>(none)</li>"

    appendix = "".join(
        f"<li><b>{esc(e['eid'])}</b> <code>{esc(e['tool'])}({esc(str(e['args']))})</code></li>"
        for e in log.all())
    return f"""<!doctype html><meta charset="utf-8"><title>DLL report</title>
<style>body{{font-family:system-ui,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem}}
code{{background:#f4f4f4;padding:1px 4px}} .obs{{color:#1a6}} .inf{{color:#a60}} .unk{{color:#888}}
table{{border-collapse:collapse}} td{{border:1px solid #ddd;padding:2px 8px}}</style>
<h1>DLL Analysis Report</h1>
<p><b>Question:</b> {esc(question)}</p>
<h2>1. Summary</h2><p>{esc(answer)}</p>
<h2>2. Triage</h2><table>{rows}</table>
<h2 class="obs">3. Observed facts</h2><ul>{items(OBSERVED)}</ul>
<h2 class="inf">4. Inferences</h2><ul>{items(INFERRED)}</ul>
<h2 class="unk">5. Unknowns and limitations</h2><ul>{items(UNKNOWN)}</ul>
<h2>6. Evidence appendix</h2><ul>{appendix}</ul>"""
