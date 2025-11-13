from __future__ import annotations

from typing import Any


def _normalize_dns_map(d: dict[str, list[str]] | None) -> dict[str, list[str]]:
    """
    Normalise la map DNS sous forme:
    { "A": ["1.2.3.4", ...], "MX": ["mx1...", ...] }
    -> chaque liste est triée et sans doublons.
    """
    if not isinstance(d, dict):
        return {}

    out: dict[str, list[str]] = {}
    for rtype, values in d.items():
        if not isinstance(values, list):
            continue
        uniq = sorted({str(v) for v in values})
        out[str(rtype)] = uniq
    return out


def _simple_list_diff(old: list[str], new: list[str]) -> dict[str, list[str]]:
    """
    Retourne {added: [...], removed: [...]} entre deux listes.
    """
    old_set: set[str] = {str(x) for x in old}
    new_set: set[str] = {str(x) for x in new}
    added = sorted(new_set - old_set)
    removed = sorted(old_set - new_set)
    return {
        "added": added,
        "removed": removed,
    }


def _takeover_key(entry: dict[str, Any]) -> tuple:
    """
    Clef stable pour comparer deux résultats de takeover.

    On ne garde que les champs importants, en ignorant l'ordre
    ou les petits détails supplémentaires.
    """
    if not isinstance(entry, dict):
        return ()

    return (
        str(entry.get("host", "")),
        str(entry.get("provider", "")),
        str(entry.get("method", "")),
        str(entry.get("match", "")),
        str(entry.get("scheme", "")),
        str(entry.get("status", "")),
    )


def diff_reports(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """
    Calcule les différences entre deux rapports de snapshot.

    Structure retournée:

    {
      "meta": {
        "from": "...",
        "to":   "..."
      },
      "dns": {
        "A":   {"added": [...], "removed": [...]},
        "MX":  {...},
        ...
      },
      "crt_subdomains": {
        "added": [...],
        "removed": [...]
      },
      "takeover": {
        "added": [...],   # liste de dicts
        "removed": [...]  # liste de dicts
      }
    }
    """
    # --- meta ---
    meta = {
        "from": old.get("timestamp") or "",
        "to": new.get("timestamp") or "",
    }

    # --- DNS ---
    old_dns = _normalize_dns_map(old.get("dns") or {})
    new_dns = _normalize_dns_map(new.get("dns") or {})

    dns_diff: dict[str, dict[str, list[str]]] = {}
    all_rtypes = sorted(set(old_dns.keys()) | set(new_dns.keys()))
    for rtype in all_rtypes:
        o_list = old_dns.get(rtype, [])
        n_list = new_dns.get(rtype, [])
        d = _simple_list_diff(o_list, n_list)
        if d["added"] or d["removed"]:
            dns_diff[rtype] = d

    # --- CRT subdomains ---
    old_crt = sorted({str(x) for x in (old.get("crt_subdomains") or [])})
    new_crt = sorted({str(x) for x in (new.get("crt_subdomains") or [])})
    crt_diff = _simple_list_diff(old_crt, new_crt)

    # --- Takeover ---
    old_to = old.get("takeover_checks") or []
    new_to = new.get("takeover_checks") or []

    old_map = {_takeover_key(e): e for e in old_to if _takeover_key(e)}
    new_map = {_takeover_key(e): e for e in new_to if _takeover_key(e)}

    old_keys = set(old_map.keys())
    new_keys = set(new_map.keys())

    added_keys = sorted(new_keys - old_keys)
    removed_keys = sorted(old_keys - new_keys)

    takeover_diff = {
        "added": [new_map[k] for k in added_keys],
        "removed": [old_map[k] for k in removed_keys],
    }

    return {
        "meta": meta,
        "dns": dns_diff,
        "crt_subdomains": crt_diff,
        "takeover": takeover_diff,
    }


def diff_snapshots(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """
    Alias simple pour compat éventuelle.
    """
    return diff_reports(old, new)


# ---------------------------------------------------------------------------
# HTML EXPORT
# ---------------------------------------------------------------------------


def _html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def diff_to_html(domain: str, diff: dict[str, Any]) -> str:
    """
    Génère un rapport HTML autonome (un seul fichier) à partir d'un diff.
    """
    meta = diff.get("meta") or {}
    dns = diff.get("dns") or {}
    crt = diff.get("crt_subdomains") or {}
    takeover = diff.get("takeover") or {}

    title = f"recondns diff report — {domain}"

    # Styles simples inline (pas de CSS externe)
    css = """
    body {
        font-family: system-ui, -apple-system, 
        BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: #0f172a;
        color: #e5e7eb;
        margin: 0;
        padding: 0;
    }
    .container {
        max-width: 1100px;
        margin: 2rem auto;
        padding: 1.5rem 2rem 3rem 2rem;
        background: #020617;
        border-radius: 1rem;
        box-shadow: 0 20px 40px rgba(0,0,0,0.4);
        border: 1px solid #1e293b;
    }
    h1, h2, h3 {
        color: #f9fafb;
    }
    h1 {
        font-size: 1.8rem;
        margin-bottom: 0.5rem;
    }
    .meta {
        font-size: 0.9rem;
        color: #9ca3af;
        margin-bottom: 1.5rem;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 1rem 0 2rem 0;
        font-size: 0.9rem;
    }
    th, td {
        border: 1px solid #1f2937;
        padding: 0.5rem 0.75rem;
        vertical-align: top;
    }
    th {
        background: #111827;
        text-align: left;
    }
    tr:nth-child(even) td {
        background: #020617;
    }
    tr:nth-child(odd) td {
        background: #020617;
    }
    .badge-added {
        display: inline-block;
        padding: 0.15rem 0.4rem;
        border-radius: 999px;
        background: #16a34a33;
        color: #4ade80;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .badge-removed {
        display: inline-block;
        padding: 0.15rem 0.4rem;
        border-radius: 999px;
        background: #b91c1c33;
        color: #fca5a5;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .pill {
        display: inline-block;
        padding: 0.1rem 0.5rem;
        border-radius: 999px;
        background: #1f2933;
        margin: 0.1rem 0.2rem 0.1rem 0;
        font-family: ui-monospace, SFMono-Regular, Menlo, 
        Monaco, Consolas, "Liberation Mono", "Courier New", 
        monospace;
        font-size: 0.8rem;
    }
    .section {
        margin-top: 2rem;
    }
    .muted {
        color: #6b7280;
        font-size: 0.85rem;
    }
    """

    html_parts: list[str] = []

    html_parts.append("<!DOCTYPE html>")
    html_parts.append("<html lang='en'>")
    html_parts.append("<head>")
    html_parts.append("<meta charset='utf-8'>")
    html_parts.append(f"<title>{_html_escape(title)}</title>")
    html_parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    html_parts.append("<style>")
    html_parts.append(css)
    html_parts.append("</style>")
    html_parts.append("</head>")
    html_parts.append("<body>")
    html_parts.append("<div class='container'>")

    # Header
    html_parts.append(f"<h1>{_html_escape(title)}</h1>")
    html_parts.append(
        f"<div class='meta'>"
        f"<div><strong>Domaine :</strong> {_html_escape(domain)}</div>"
        f"<div><strong>From :</strong> {_html_escape(str(meta.get('from') or ''))}</div>"
        f"<div><strong>To :</strong> {_html_escape(str(meta.get('to') or ''))}</div>"
        f"</div>"
    )

    # DNS section
    html_parts.append("<div class='section'>")
    html_parts.append("<h2>DNS Changes</h2>")
    if dns:
        html_parts.append("<table>")
        html_parts.append("<tr><th>Type</th><th>Ajoutés</th><th>Supprimés</th></tr>")
        for rtype, changes in dns.items():
            added = changes.get("added") or []
            removed = changes.get("removed") or []
            added_html = (
                "<span class='badge-added'>+ added</span><br>"
                + "".join(f"<span class='pill'>{_html_escape(a)}</span>" for a in added)
                if added
                else "<span class='muted'>—</span>"
            )
            removed_html = (
                "<span class='badge-removed'>– removed</span><br>"
                + "".join(f"<span class='pill'>{_html_escape(r)}</span>" for r in removed)
                if removed
                else "<span class='muted'>—</span>"
            )
            html_parts.append(
                "<tr>"
                f"<td><strong>{_html_escape(str(rtype))}</strong></td>"
                f"<td>{added_html}</td>"
                f"<td>{removed_html}</td>"
                "</tr>"
            )
        html_parts.append("</table>")
    else:
        html_parts.append("<p class='muted'>Aucun changement DNS détecté.</p>")
    html_parts.append("</div>")  # DNS section

    # CRT section
    html_parts.append("<div class='section'>")
    html_parts.append("<h2>CRT Subdomains</h2>")
    if crt.get("added") or crt.get("removed"):
        html_parts.append("<table>")
        html_parts.append("<tr><th>Ajoutés</th><th>Supprimés</th></tr>")
        added = crt.get("added") or []
        removed = crt.get("removed") or []
        added_html = (
            "<span class='badge-added'>+ added</span><br>"
            + "".join(f"<span class='pill'>{_html_escape(a)}</span>" for a in added)
            if added
            else "<span class='muted'>—</span>"
        )
        removed_html = (
            "<span class='badge-removed'>– removed</span><br>"
            + "".join(f"<span class='pill'>{_html_escape(r)}</span>" for r in removed)
            if removed
            else "<span class='muted'>—</span>"
        )
        html_parts.append(f"<tr><td>{added_html}</td><td>{removed_html}</td></tr>")
        html_parts.append("</table>")
    else:
        html_parts.append("<p class='muted'>Aucun changement de sous-domaines CRT.</p>")
    html_parts.append("</div>")  # CRT section

    # Takeover section
    html_parts.append("<div class='section'>")
    html_parts.append("<h2>Takeover Findings</h2>")
    to_added = takeover.get("added") or []
    to_removed = takeover.get("removed") or []

    if to_added or to_removed:
        html_parts.append("<table>")
        html_parts.append(
            "<tr><th>Type</th><th>Host</th><th>Provider</th><th>Method</th><th>Status</th><th>Match</th></tr>"
        )

        for e in to_added:
            html_parts.append(
                "<tr>"
                "<td><span class='badge-added'>+ added</span></td>"
                f"<td>{_html_escape(str(e.get('host', '')))}</td>"
                f"<td>{_html_escape(str(e.get('provider', '')))}</td>"
                f"<td>{_html_escape(str(e.get('method', '')))}</td>"
                f"<td>{_html_escape(str(e.get('status', '')))}</td>"
                f"<td>{_html_escape(str(e.get('match', '')))}</td>"
                "</tr>"
            )

        for e in to_removed:
            html_parts.append(
                "<tr>"
                "<td><span class='badge-removed'>– removed</span></td>"
                f"<td>{_html_escape(str(e.get('host', '')))}</td>"
                f"<td>{_html_escape(str(e.get('provider', '')))}</td>"
                f"<td>{_html_escape(str(e.get('method', '')))}</td>"
                f"<td>{_html_escape(str(e.get('status', '')))}</td>"
                f"<td>{_html_escape(str(e.get('match', '')))}</td>"
                "</tr>"
            )

        html_parts.append("</table>")
    else:
        html_parts.append("<p class='muted'>Aucun changement dans les findings de takeover.</p>")
    html_parts.append("</div>")  # Takeover section

    html_parts.append("</div>")  # container
    html_parts.append("</body>")
    html_parts.append("</html>")

    return "".join(html_parts)
