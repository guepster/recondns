from __future__ import annotations
from typing import Dict, Any, Tuple, Set

def _index(records: Any) -> Set[Tuple[str, str, str]]:
    """
    Normalise un enregistrement en triplet (name, type, value).
    On accepte:
      - dicts style {"name": "...", "type": "A", "value": "1.2.3.4"}
      - ou objets déjà normalisés
    """
    idx = set()
    for r in records or []:
        name = (r.get("name") or "").lower()
        rtype = (r.get("type") or "").upper()
        value = str(r.get("value") or "").strip()
        idx.add((name, rtype, value))
    return idx

def diff_snapshots(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    # On suppose que l’outil retourne un dict avec au moins "records": [ {name,type,value,...}, ... ]
    old_idx = _index(old.get("records"))
    new_idx = _index(new.get("records"))

    added = sorted(list(new_idx - old_idx))
    removed = sorted(list(old_idx - new_idx))
    unchanged = sorted(list(new_idx & old_idx))

    # Optionnel : changements de "proof"/"takeover" par sous-domaine (si présent)
    takeover_changes = []
    old_map = {(r["name"].lower(), r.get("type","").upper(), str(r.get("value",""))): r for r in (old.get("records") or []) if "name" in r}
    for r in (new.get("records") or []):
        key = (r.get("name","").lower(), r.get("type","").upper(), str(r.get("value","")))
        o = old_map.get(key)
        if o:
            if (o.get("takeover_risk") != r.get("takeover_risk")) or (o.get("proof") != r.get("proof")):
                takeover_changes.append({"key": key, "old": {"risk": o.get("takeover_risk"), "proof": o.get("proof")},
                                                "new": {"risk": r.get("takeover_risk"), "proof": r.get("proof")}})

    return {
        "added": added,
        "removed": removed,
        "unchanged": unchanged,
        "takeover_changes": takeover_changes
    }
