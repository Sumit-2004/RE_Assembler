"""Draw control-flow graphs from the extracted blocks (Part 1, Phase 4).

We draw the graph ourselves rather than screenshotting another tool, so the data
is exact and the layout is ours. Edge colours follow the IDA convention:
    green = conditional branch taken, red = fall-through, blue = unconditional.

Two outputs:
    render_svg  -- one static SVG per function (Graphviz), good for the report.
    render_html -- an interactive Cytoscape.js page; clicking a block opens a
                   side panel with the full explanation and per-instruction notes.
The HTML output is self-contained text and needs no backend, so it works even
where Graphviz is not installed.
"""
import html
import json
import os

from . import backends


def _node_label(block: dict, note: dict) -> str:
    asm = "\\l".join(block.get("asm", []))
    summary = (note or {}).get("summary", "")
    return f"{asm}\\l\\n{summary}\\l"


def render_svg(func: dict, notes: dict, out_dir: str = "out") -> str:
    """Render one function's CFG to an SVG with Graphviz. Returns the file path.

    Args:
        func: a function dict from disasm.get_function (blocks with jump/fail)
        notes: {block_addr: explanation} from explain.explain_block
        out_dir: directory to write <function>.svg into
    """
    graphviz = backends.require("graphviz", "sudo apt install graphviz && pip install graphviz")
    os.makedirs(out_dir, exist_ok=True)
    g = graphviz.Digraph(node_attr={"shape": "box", "fontname": "Consolas", "fontsize": "10"})
    for b in func["blocks"]:
        g.node(b["addr"], _node_label(b, notes.get(b["addr"], {})))
        if b.get("jump"):
            g.edge(b["addr"], b["jump"], color="green" if b.get("fail") else "blue")
        if b.get("fail"):
            g.edge(b["addr"], b["fail"], color="red")
    safe = func["name"].replace("/", "_").replace("\\", "_") or func["addr"]
    return g.render(os.path.join(out_dir, safe), format="svg", cleanup=True)


_HTML_TEMPLATE = """<!doctype html>
<meta charset="utf-8">
<title>CFG: {name}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.2/cytoscape.min.js"></script>
<style>
  body {{ margin: 0; font-family: Consolas, monospace; display: flex; }}
  #cy {{ flex: 1; height: 100vh; }}
  #panel {{ width: 420px; padding: 16px; overflow: auto; border-left: 1px solid #ccc; }}
  pre {{ white-space: pre-wrap; }}
</style>
<div id="cy"></div>
<div id="panel"><h3>{name}</h3><p>Click a block.</p></div>
<script>
const NOTES = {notes};
cytoscape({{
  container: document.getElementById('cy'),
  elements: {elements},
  layout: {{ name: 'breadthfirst', directed: true, spacingFactor: 1.2 }},
  style: [
    {{ selector: 'node', style: {{ 'shape': 'round-rectangle', 'background-color': '#eef',
        'border-color': '#557', 'border-width': 1, 'label': 'data(addr)',
        'text-valign': 'center', 'font-family': 'Consolas', 'font-size': 10, 'width': 'label', 'padding': 8 }} }},
    {{ selector: 'edge', style: {{ 'width': 2, 'line-color': 'data(color)',
        'target-arrow-color': 'data(color)', 'target-arrow-shape': 'triangle',
        'curve-style': 'bezier' }} }}
  ]
}}).on('tap', 'node', e => {{
  const n = NOTES[e.target.id()] || {{}};
  document.getElementById('panel').innerHTML =
    '<h3>' + e.target.id() + '</h3><p><b>' + (n.summary||'') + '</b></p><p>' +
    (n.detail||'') + '</p><pre>' + (n.asm||'') + '</pre>';
}});
</script>
"""


def render_html(func: dict, notes: dict, out_dir: str = "out") -> str:
    """Render an interactive Cytoscape.js CFG page. Returns the file path."""
    os.makedirs(out_dir, exist_ok=True)
    elements = []
    enriched = {}
    for b in func["blocks"]:
        elements.append({"data": {"id": b["addr"], "addr": b["addr"]}})
        n = dict(notes.get(b["addr"], {}))
        n["asm"] = html.escape("\n".join(b.get("asm", [])))
        enriched[b["addr"]] = n
        if b.get("jump"):
            elements.append({"data": {"source": b["addr"], "target": b["jump"],
                                      "color": "green" if b.get("fail") else "blue"}})
        if b.get("fail"):
            elements.append({"data": {"source": b["addr"], "target": b["fail"], "color": "red"}})
    page = _HTML_TEMPLATE.format(
        name=html.escape(func["name"] or func["addr"]),
        notes=json.dumps(enriched),
        elements=json.dumps(elements),
    )
    safe = (func["name"] or func["addr"]).replace("/", "_").replace("\\", "_")
    path = os.path.join(out_dir, safe + ".html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(page)
    return path
