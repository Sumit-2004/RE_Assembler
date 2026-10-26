"""Lazy imports for the optional analysis backends.

The static layer (``tools.py``) only needs ``pefile`` and runs on Windows.
The disassembly, LLM, capability and .NET layers need tools that only install
cleanly on the Linux VM (radare2, Ollama, capa, FLOSS, dnfile). Importing the
package must never fail just because those are absent, so every backend is
imported on first use through one of the helpers below, which raise a single
clear message naming what to install.
"""
import importlib
import importlib.util


class BackendMissing(RuntimeError):
    """A backend tool or Python package needed for this stage is not installed."""


def require(module: str, install_hint: str):
    """Import ``module`` or raise ``BackendMissing`` with an install hint."""
    try:
        return importlib.import_module(module)
    except ImportError as exc:  # pragma: no cover - exercised only without the backend
        raise BackendMissing(
            f"'{module}' is not installed. This stage needs it: {install_hint}"
        ) from exc


def have(module: str) -> bool:
    """Return True if ``module`` can be imported, without raising."""
    return importlib.util.find_spec(module) is not None
