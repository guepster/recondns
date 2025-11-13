from typing import Any


def _as_set(lst):
    return set(lst or [])


def _dict_sets(d):
    return {k: _as_set(v) for k, v in (d or {}).items()}


def diff_reports(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """
    Compare deux reports (snapshots) recondns et retourne un dict:
    - dns: par type (A, NS, MX, TXT, CNAME...) -> added/removed
    - crt_subdomains: added/removed
    - takeover: added/removed (par host+provider)
    """
    out = {
        "meta": {"domain": a.get("domain"), "from": a.get("timestamp"), "to": b.get("timestamp")},
        "dns": {},
        "crt_subdomains": {},
        "takeover": {},
    }

    # DNS diffs
    dns_a = _dict_sets(a.get("dns"))
    dns_b = _dict_sets(b.get("dns"))
    keys = set(dns_a.keys()) | set(dns_b.keys())
    for k in sorted(keys):
        added = sorted(list(dns_b.get(k, set()) - dns_a.get(k, set())))
        removed = sorted(list(dns_a.get(k, set()) - dns_b.get(k, set())))
        if added or removed:
            out["dns"][k] = {"added": added, "removed": removed}

    # CRT subdomains diffs
    subs_a = _as_set(a.get("crt_subdomains"))
    subs_b = _as_set(b.get("crt_subdomains"))
    sub_added = sorted(list(subs_b - subs_a))
    sub_removed = sorted(list(subs_a - subs_b))
    if sub_added or sub_removed:
        out["crt_subdomains"] = {"added": sub_added, "removed": sub_removed}

    # takeover diffs (host+provider key)
    def _tk_set(report):
        s = set()
        for item in report.get("takeover_checks") or []:
            key = f"{item.get('host')}|{item.get('provider')}"
            s.add(key)
        return s

    tk_a = _tk_set(a)
    tk_b = _tk_set(b)
    tk_added = sorted(list(tk_b - tk_a))
    tk_removed = sorted(list(tk_a - tk_b))
    if tk_added or tk_removed:
        out["takeover"] = {"added": tk_added, "removed": tk_removed}

    return out
