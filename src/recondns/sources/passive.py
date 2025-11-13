# src/recondns/sources/passive.py

import os
import logging
from typing import Iterable, Set, Callable, Optional, List
import requests

logger = logging.getLogger("recondns.passive")

USER_AGENT = "recondns/0.2 (+https://github.com/yourname/recondns-cli)"

# ------------------ Utils ------------------


def _normalize_name(name: str, domain: str) -> Optional[str]:
    """Nettoie un nom : enlève les wildcards, espaces, garde seulement les sous-domaines du domain."""
    if not isinstance(name, str):
        return None
    n = name.strip().lower()
    if not n:
        return None
    # enlève les wildcards
    n = n.lstrip("*.")  # *.example.com -> example.com
    # garde seulement ce qui appartient au domaine ciblé
    if not n.endswith(domain):
        return None
    return n


def _dedupe_filter(names: Iterable[str], domain: str) -> Set[str]:
    out: Set[str] = set()
    for n in names:
        nn = _normalize_name(n, domain)
        if nn:
            out.add(nn)
    return out


# ------------------ CertSpotter ------------------


def certspotter(domain: str) -> Set[str]:
    """
    Récupère les sous-domaines via CertSpotter.

    - Utilise l'endpoint public v1
    - Si CERTSPOTTER_API_TOKEN est défini dans l'env, on ajoute un header Authorization.
    - On ne gère qu'une page (suffisant pour un petit outil perso).
    """
    url = "https://api.certspotter.com/v1/issuances"
    params = {
        "domain": domain,
        "include_subdomains": "true",
        "expand": "dns_names",
        "match_wildcards": "true",
    }

    headers = {"User-Agent": USER_AGENT}
    token = os.getenv("CERTSPOTTER_API_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=15)
        if resp.status_code != 200:
            logger.warning("CertSpotter HTTP %s for %s", resp.status_code, domain)
            return set()
        data = resp.json()
        found: Set[str] = set()
        for entry in data:
            dns_names = entry.get("dns_names") or []
            for name in dns_names:
                nn = _normalize_name(name, domain)
                if nn:
                    found.add(nn)
        return found
    except Exception as e:
        logger.warning("CertSpotter error for %s: %s", domain, e)
        return set()


# ------------------ BufferOver (dns.bufferover.run) ------------------


def bufferover(domain: str) -> Set[str]:
    """
    Utilise dns.bufferover.run pour récupérer des sous-domaines à partir des enregistrements FDNS_A / FDNS_CNAME.
    """
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            logger.warning("BufferOver HTTP %s for %s", resp.status_code, domain)
            return set()
        data = resp.json()
        candidates: Set[str] = set()

        for key in ("FDNS_A", "FDNS_CNAME"):
            entries = data.get(key) or []
            for line in entries:
                # format typique : "1.2.3.4,sub.example.com"
                if not isinstance(line, str):
                    continue
                parts = line.split(",")
                if len(parts) == 2:
                    host = parts[1].strip()
                    candidates.add(host)
                else:
                    # parfois juste un hostname
                    candidates.add(line.strip())
        return _dedupe_filter(candidates, domain)
    except Exception as e:
        logger.warning("BufferOver error for %s: %s", domain, e)
        return set()


# ------------------ HackerTarget (fallback léger) ------------------


def hackertarget(domain: str) -> Set[str]:
    """
    Utilise l'API gratuite de HackerTarget (limites fortes, mais utile en fallback).

    Endpoint : https://api.hackertarget.com/hostsearch/?q=example.com
    Format : "sub.example.com,1.2.3.4" par ligne.
    """
    url = "https://api.hackertarget.com/hostsearch/"
    params = {"q": domain}
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=15)
        # HackerTarget renvoie 200 même en cas d'erreur, souvent sous forme de texte. On filtre un peu.
        if resp.status_code != 200:
            logger.warning("HackerTarget HTTP %s for %s", resp.status_code, domain)
            return set()
        text = resp.text
        candidates: Set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or "," not in line:
                continue
            host, _ip = line.split(",", 1)
            candidates.add(host.strip())
        return _dedupe_filter(candidates, domain)
    except Exception as e:
        logger.warning("HackerTarget error for %s: %s", domain, e)
        return set()


# ------------------ Orchestrateur ------------------


def gather_passive(
    domain: str,
    sources: Optional[List[Callable[[str], Set[str]]]] = None,
) -> Set[str]:
    """
    Combine plusieurs sources passives en un seul set de sous-domaines.
    Par défaut : CertSpotter + BufferOver + HackerTarget.
    """
    if sources is None:
        sources = [certspotter, bufferover, hackertarget]

    all_names: Set[str] = set()
    for fn in sources:
        try:
            subnames = fn(domain)
            if subnames:
                logger.info("[passive] %s -> %d sous-domaines", fn.__name__, len(subnames))
            all_names.update(subnames)
        except Exception as e:
            logger.warning("Passive source %s failed for %s: %s", fn.__name__, domain, e)

    return _dedupe_filter(all_names, domain)


__all__ = ["certspotter", "bufferover", "hackertarget", "gather_passive"]
