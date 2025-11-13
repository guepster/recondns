# src/recondns/sources/passive.py
"""
Sources passives : certspotter, bufferover.run (BufferOver).
Retourne un set de sous-domaines découverts.
"""

from typing import Set, Iterable
import requests
import logging

LOG = logging.getLogger("recondns.passive")

def certspotter(domain: str, limit: int = 100) -> Set[str]:
    """
    Interroge l'API publique de CertSpotter.
    Pas d'API key nécessaire pour requêtes basiques.
    """
    url = "https://api.certspotter.com/v1/issuances"
    params = {
        "domain": domain,
        "include_subdomains": "true",
        "expand": "dns_names",
        "per_page": limit
    }
    subs: Set[str] = set()
    try:
        r = requests.get(url, params=params, timeout=8)
        r.raise_for_status()
        for item in r.json():
            for name in item.get("dns_names", []) or []:
                if isinstance(name, str) and name.endswith(domain):
                    subs.add(name.lower().rstrip("."))
    except Exception as e:
        LOG.debug("certspotter error for %s: %s", domain, e)
    return subs


def bufferover(domain: str) -> Set[str]:
    """
    Interroge bufferover.run public endpoint (dns.bufferover.run).
    Retourne un set de noms extraits des champs FDNS_A / RDNS etc.
    """
    url = f"https://dns.bufferover.run/dns?q={domain}"
    subs: Set[str] = set()
    try:
        r = requests.get(url, timeout=8)
        r.raise_for_status()
        data = r.json()
        # FDNS_A entries format: "ip,sub.domain" ou list similaire
        for key in ("FDNS_A", "RDNS", "FDNS_CNAME"):
            for entry in data.get(key, []) or []:
                if not isinstance(entry, str):
                    continue
                parts = entry.split(",")
                candidate = parts[-1].strip()
                if candidate.endswith(domain):
                    subs.add(candidate.lower().rstrip("."))
    except Exception as e:
        LOG.debug("bufferover error for %s: %s", domain, e)
    return subs


def gather_passive(domain: str, sources: Iterable[str] = ("crtsh", "certspotter", "bufferover")) -> Set[str]:
    """
    Wrapper qui combine plusieurs sources passives.
    'crtsh' reste géré ailleurs — on inclut ici certspotter & bufferover.
    """
    out: Set[str] = set()
    for s in sources:
        if s == "certspotter":
            out |= certspotter(domain)
        elif s == "bufferover" or s == "buffer":
            out |= bufferover(domain)
        # leave 'crtsh' to existing implementation
    return out
