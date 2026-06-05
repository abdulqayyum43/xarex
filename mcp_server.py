#!/usr/bin/env python3
"""MCP Filesystem server — Xarex frontend project."""

import os
from pathlib import Path
from mcp.server.fastmcp import FastMCP

ROOT = Path(r"C:\Users\abdul\OneDrive\Desktop\projs\phantom\frontend")

mcp = FastMCP("xarex-frontend")


@mcp.tool()
def read_file(path: str) -> str:
    """Read any file in the Xarex frontend project (relative to frontend/)."""
    return (ROOT / path).read_text(encoding="utf-8")


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Overwrite a file in the Xarex frontend project."""
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return f"wrote {target.stat().st_size} bytes → {path}"


@mcp.tool()
def edit_file(path: str, old_text: str, new_text: str) -> str:
    """Replace the first occurrence of old_text with new_text in a file."""
    target = ROOT / path
    src = target.read_text(encoding="utf-8")
    if old_text not in src:
        return f"ERROR: text not found in {path}"
    target.write_text(src.replace(old_text, new_text, 1), encoding="utf-8")
    return f"edit applied → {path}"


@mcp.tool()
def list_files(directory: str = ".") -> list[str]:
    """List all files under a directory (relative to frontend/)."""
    base = ROOT / directory
    return sorted(str(p.relative_to(ROOT)) for p in base.rglob("*") if p.is_file())


@mcp.tool()
def grep(pattern: str, path: str = ".") -> list[str]:
    """Search for a regex pattern across project files, returns 'file:lineno: line'."""
    import re
    results: list[str] = []
    base = ROOT / path
    targets = [base] if base.is_file() else list(base.rglob("*.html")) + list(base.rglob("*.css")) + list(base.rglob("*.js"))
    for f in targets:
        try:
            for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(pattern, line):
                    results.append(f"{f.relative_to(ROOT)}:{i}: {line.strip()}")
        except Exception:
            pass
    return results


if __name__ == "__main__":
    mcp.run()
