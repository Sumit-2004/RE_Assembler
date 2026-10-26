"""The shared tool registry, exposed two ways (Part 2).

The same analysis functions back both the MCP server (server.py, for Claude Code
or any MCP client) and the local Qwen agent loop (agent.py). Keeping one list
here means the two front-ends can never drift apart. Each tool is small and
specific -- a 7B-14B model chooses well between many clear tools and badly
between a few vague ones -- and every tool is read-only.
"""
from . import capabilities, disasm, dotnet, tools

# Order roughly matches a triage workflow: identify, enumerate, drill in.
TOOLS = [
    tools.triage_dll,
    tools.list_exports,
    tools.list_imports,
    capabilities.find_capabilities,
    capabilities.search_strings,
    disasm.list_functions,
    disasm.get_function,
    disasm.xrefs_to,
    dotnet.inspect_dotnet,
]

BY_NAME = {fn.__name__: fn for fn in TOOLS}
