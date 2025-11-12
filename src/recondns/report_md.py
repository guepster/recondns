from __future__ import annotations
from typing import Dict, Any, Iterable

def _lines(title: str, rows: Iterable[tuple]) -> str:
    out = [f"### {title}", "", "| name | type | value |", "|---|---|---|"]
    for (n,t,v) in rows:
        out.append(f"| `{n}` | `{t}` | `{v}` |")
    out.append("")
    return "\n".join(out)

def render_diff_md(diff: Dict[str, Any]) -> str:
    md = ["# Subdomain diff report", ""]
    if diff["added"]:
        md.append(_lines("Added", diff["added"]))
    if diff["removed"]:
        md.append(_lines("Removed", diff["removed"]))
    if diff["takeover_changes"]:
        md.append("### Takeover status changed\n")
        md.append("| name | type | value | old | new |")
        md.append("|---|---|---|---|---|")
        for d in diff["takeover_changes"]:
            (n,t,v) = d["key"]
            old = d["old"]["risk"]
            new = d["new"]["risk"]
            md.append(f"| `{n}` | `{t}` | `{v}` | `{old}` | `{new}` |")
        md.append("")
    if not (diff["added"] or diff["removed"] or diff["takeover_changes"]):
        md.append("_No change._\n")
    return "\n".join(md)
