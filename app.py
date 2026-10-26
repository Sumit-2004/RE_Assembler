"""Streamlit UI (Part 1, Phase 5).

Upload a DLL, see its triage, pick a function (exports first), view the rendered
CFG and read the per-block explanation. A "Download report" button saves
everything as Markdown.

    streamlit run app.py

Needs: pip install streamlit. The explain/render panels need the Linux backends.
"""
import os
import tempfile

import streamlit as st

from dll_analyzer import disasm, explain, render, tools


st.set_page_config(page_title="AI Assembly Explainer", layout="wide")
st.title("AI Assembly Explainer")
st.caption("The disassembler supplies the facts; a local Qwen model only explains them.")

uploaded = st.file_uploader("Upload a DLL / LIB / .so you are allowed to analyse", type=["dll", "so", "lib"])
if not uploaded:
    st.info("Analyse only DLLs you compiled, open-source libraries, or software whose licence permits RE.")
    st.stop()

tmp_dir = tempfile.mkdtemp()
path = os.path.join(tmp_dir, uploaded.name)
with open(path, "wb") as fh:
    fh.write(uploaded.getbuffer())

triage = tools.triage_dll(path)
st.subheader("Triage")
st.json(triage)

if triage["runtime"] == ".NET":
    st.warning("Managed (.NET) DLL -- route to the .NET branch (dll_analyzer.dotnet), not the native pipeline.")
    st.stop()

exports = {e["name"] for e in tools.list_exports(path)}
funcs = disasm.list_functions(path)["functions"]
funcs.sort(key=lambda f: (f["name"] not in exports, f["name"]))  # exports first
choice = st.selectbox("Function", [f"{f['name']}  ({f['addr']})" for f in funcs])
addr = choice.split("(")[-1].rstrip(")").strip()

func = disasm.get_function(path, addr)
import_names = [i["function"] for i in tools.list_imports(path)]
notes = {}
with st.spinner("Explaining blocks with Qwen..."):
    for block in func["blocks"]:
        notes[block["addr"]] = explain.explain_block(
            block, func["name"], func["name"] in exports, import_names,
            strings=[], pseudo_c=func.get("pseudo_c", ""), arch=triage["arch"])

col1, col2 = st.columns([3, 2])
with col1:
    svg = render.render_svg(func, notes, tmp_dir)
    st.image(svg)
with col2:
    for b in func["blocks"]:
        n = notes[b["addr"]]
        with st.expander(f"{b['addr']} — {n.get('summary', '')}"):
            st.write(n.get("detail", ""))
            if n.get("unverified"):
                st.warning("Unverified names: " + ", ".join(n["unverified"]))
            st.code("\n".join(b["asm"]))

md = [f"# {uploaded.name}", f"## {func['name']}"]
for b in func["blocks"]:
    md.append(f"### {b['addr']}\n{notes[b['addr']].get('detail', '')}")
st.download_button("Download report (Markdown)", "\n".join(md), file_name="report.md")
