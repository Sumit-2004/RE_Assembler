"""MCP server exposing the DLL analysis tools (Part 2, Week 5).

Registers every tool in the shared registry so any MCP client -- your own Qwen
agent, Claude Code, or Cursor -- can use the same read-only API. Test it with a
strong model first:

    claude mcp add dll-analyzer -- python /absolute/path/server.py

Needs: pip install "mcp[cli]". The individual tools need their own backends
(radare2, capa, ...) only when called.
"""
from dll_analyzer.registry import TOOLS


def main() -> None:
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("dll-analyzer")
    for fn in TOOLS:
        mcp.tool()(fn)  # the docstrings become the tool descriptions the model reads
    mcp.run()  # stdio transport


if __name__ == "__main__":
    main()
