from typing import Dict, Any, List


def _fmt_list(items: List[str]) -> str:
    if not items:
        return "-"
    return ", ".join(sorted(items))


def render_diff_md(diff: Dict[str, Any]) -> str:
    meta = diff.get("meta", {})
    domain = meta.get("domain", "?")
    ts_from = meta.get("from", "?")
    ts_to = meta.get("to", "?")

    lines: List[str] = []
    lines.append(f"# Diff recondns — {domain}")
    lines.append("")
    lines.append(f"_De_ **{ts_from}** _à_ **{ts_to}**")
    lines.append("")

    # DNS
    dns = diff.get("dns") or {}
    if dns:
        lines.append("## DNS")
        lines.append("")
        lines.append("| Type | Ajouts | Retraits |")
        lines.append("|------|--------|----------|")
        for rtype, changes in dns.items():
            added = _fmt_list(changes.get("added") or [])
            removed = _fmt_list(changes.get("removed") or [])
            lines.append(f"| {rtype} | {added} | {removed} |")
        lines.append("")

    # CRT subdomains
    crt = diff.get("crt_subdomains") or {}
    if crt:
        lines.append("## Sous-domaines (CRT + passif)")
        lines.append("")
        added = crt.get("added") or []
        removed = crt.get("removed") or []
        if added:
            lines.append("**Ajoutés :**")
            for s in added:
                lines.append(f"- `{s}`")
            lines.append("")
        if removed:
            lines.append("**Retirés :**")
            for s in removed:
                lines.append(f"- `{s}`")
            lines.append("")

    # Takeover
    takeover = diff.get("takeover") or {}
    if takeover:
        lines.append("## Takeover potentiels")
        lines.append("")
        added = takeover.get("added") or []
        removed = takeover.get("removed") or []
        if added:
            lines.append("**Nouvelles alertes :**")
            for t in added:
                host = t.get("host")
                provider = t.get("provider")
                method = t.get("method")
                status = t.get("status")
                scheme = t.get("scheme")
                lines.append(f"- `{host}` → **{provider}** ({method}, {scheme}, status={status})")
            lines.append("")
        if removed:
            lines.append("**Alertes disparues :**")
            for t in removed:
                host = t.get("host")
                provider = t.get("provider")
                lines.append(f"- `{host}` (anciennement {provider})")
            lines.append("")

    if not dns and not crt and not takeover:
        lines.append("_Aucun changement détecté._")
        lines.append("")

    return "\n".join(lines)


def render_diff_html(diff: Dict[str, Any]) -> str:
    """Version HTML autonome (un seul fichier)."""
    meta = diff.get("meta", {})
    domain = meta.get("domain", "?")
    ts_from = meta.get("from", "?")
    ts_to = meta.get("to", "?")

    # On réutilise le même découpage que pour le MD
    dns = diff.get("dns") or {}
    crt = diff.get("crt_subdomains") or {}
    takeover = diff.get("takeover") or {}

    def esc(s: Any) -> str:
        return (
            str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    html_parts: List[str] = []
    html_parts.append(
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>recondns diff — {esc(domain)}</title>"
        "<style>"
        "body{font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
        "margin:2rem;background:#0b1020;color:#e5e7eb;}"
        "h1,h2{color:#f9fafb;}"
        ".badge{display:inline-block;padding:0.15rem 0.5rem;border-radius:999px;"
        "font-size:0.75rem;margin-left:0.5rem;background:#1f2937;color:#e5e7eb;}"
        "table{border-collapse:collapse;width:100%;margin:1rem 0;background:#020617;}"
        "th,td{border:1px solid #111827;padding:0.4rem 0.6rem;font-size:0.9rem;}"
        "th{background:#111827;text-align:left;}"
        "code{background:#111827;padding:0.1rem 0.3rem;border-radius:0.25rem;}"
        "</style></head><body>"
    )

    html_parts.append(f"<h1>Diff recondns — {esc(domain)}</h1>")
    html_parts.append(
        f"<p>De <strong>{esc(ts_from)}</strong> à <strong>{esc(ts_to)}</strong></p>"
    )

    # DNS
    if dns:
        html_parts.append("<h2>DNS<span class='badge'>changements</span></h2>")
        html_parts.append(
            "<table><thead><tr><th>Type</th><th>Ajouts</th><th>Retraits</th></tr></thead><tbody>"
        )
        for rtype, changes in dns.items():
            added = ", ".join(esc(v) for v in (changes.get("added") or [])) or "-"
            removed = ", ".join(esc(v) for v in (changes.get("removed") or [])) or "-"
            html_parts.append(
                f"<tr><td>{esc(rtype)}</td><td>{added}</td><td>{removed}</td></tr>"
            )
        html_parts.append("</tbody></table>")

    # CRT subdomains
    if crt:
        added = crt.get("added") or []
        removed = crt.get("removed") or []
        html_parts.append("<h2>Sous-domaines CRT + passif</h2>")
        if added:
            html_parts.append("<h3>Ajoutés</h3><ul>")
            for s in added:
                html_parts.append(f"<li><code>{esc(s)}</code></li>")
            html_parts.append("</ul>")
        if removed:
            html_parts.append("<h3>Retirés</h3><ul>")
            for s in removed:
                html_parts.append(f"<li><code>{esc(s)}</code></li>")
            html_parts.append("</ul>")

    # Takeover
    if takeover:
        added = takeover.get("added") or []
        removed = takeover.get("removed") or []
        html_parts.append("<h2>Takeover potentiels</h2>")
        if added:
            html_parts.append("<h3>Nouvelles alertes</h3><ul>")
            for t in added:
                host = esc(t.get("host"))
                provider = esc(t.get("provider"))
                method = esc(t.get("method"))
                status = esc(t.get("status"))
                scheme = esc(t.get("scheme"))
                html_parts.append(
                    f"<li><code>{host}</code> → <strong>{provider}</strong> "
                    f"({method}, {scheme}, status={status})</li>"
                )
            html_parts.append("</ul>")
        if removed:
            html_parts.append("<h3>Alertes disparues</h3><ul>")
            for t in removed:
                host = esc(t.get("host"))
                provider = esc(t.get("provider"))
                html_parts.append(
                    f"<li><code>{host}</code> (anciennement {provider})</li>"
                )
            html_parts.append("</ul>")

    if not dns and not crt and not takeover:
        html_parts.append("<p><em>Aucun changement détecté.</em></p>")

    html_parts.append("</body></html>")
    return "".join(html_parts)
