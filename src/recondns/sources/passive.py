# src/recondns/sources/passive.py

import logging
import os
from collections.abc import Callable, Iterable

import requests

logger = logging.getLogger("recondns.passive")

USER_AGENT = "recondns/0.2 (+https://github.com/yourname/recondns-cli)"

# ------------------ Utils ------------------


def _normalize_name(name: str, domain: str) -> str | None:
    """Nettoie un nom : enlève les wildcards, espaces, garde
    seulement les sous-domaines du domain."""
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


def _dedupe_filter(names: Iterable[str], domain: str) -> set[str]:
    out: set[str] = set()
    for n in names:
        nn = _normalize_name(n, domain)
        if nn:
            out.add(nn)
    return out


# ------------------ CertSpotter ------------------


def certspotter(domain: str) -> set[str]:
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
        found: set[str] = set()
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


def bufferover(domain: str) -> set[str]:
    """
    Utilise dns.bufferover.run pour récupérer des sous-domaines à partir
    des enregistrements FDNS_A / FDNS_CNAME.
    """
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            # AVANT : logger.warning(...)
            logger.debug("BufferOver HTTP %s for %s", resp.status_code, domain)
            return set()
        data = resp.json()
        candidates: set[str] = set()

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
        # AVANT : logger.warning(...)
        logger.debug("BufferOver error for %s: %s", domain, e)
        return set()

def bufferover_safe(domain: str) -> tuple[set[str], str | None]:
    """
    Variante de Bufferover qui remonte aussi un code d'erreur symbolique.

    Retourne (subdomains, error_code):
      - subdomains : set[str] (éventuellement vide)
      - error_code : None si OK, sinon "http_error" / "network_error" / "parse_error"
    """
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    headers = {"User-Agent": USER_AGENT}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
    except requests.exceptions.RequestException as e:
        logger.debug("BufferOver network error for %s: %s", domain, e)
        return set(), "network_error"

    if resp.status_code != 200:
        logger.debug("BufferOver HTTP %s for %s", resp.status_code, domain)
        return set(), "http_error"

    try:
        data = resp.json()
    except ValueError as e:
        logger.debug("BufferOver JSON parse error for %s: %s", domain, e)
        return set(), "parse_error"

    candidates: set[str] = set()
    for key in ("FDNS_A", "FDNS_CNAME"):
        entries = data.get(key) or []
        for line in entries:
            if not isinstance(line, str):
                continue
            parts = line.split(",")
            if len(parts) == 2:
                host = parts[1].strip()
                candidates.add(host)
            else:
                candidates.add(line.strip())

    return _dedupe_filter(candidates, domain), None


# ------------------ HackerTarget (fallback léger) ------------------


def hackertarget(domain: str) -> set[str]:
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
        # HackerTarget renvoie 200 même en cas d'erreur,
        # souvent sous forme de texte. On filtre un peu.
        if resp.status_code != 200:
            logger.warning("HackerTarget HTTP %s for %s", resp.status_code, domain)
            return set()
        text = resp.text
        candidates: set[str] = set()
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
    sources: list[Callable[[str], set[str]]] | None = None,
) -> set[str]:
    """
    Version historique : ne retourne que les sous-domaines.
    Pour la nouvelle V1 enrichie, préfère gather_passive_with_status().
    """
    subs, _ = gather_passive_with_status(domain)
    return subs


__all__ = [
    "certspotter",
    "bufferover",
    "bufferover_safe",
    "hackertarget",
    "gather_passive",
    "gather_passive_with_status",
]

def gather_passive_with_status(domain: str) -> tuple[set[str], dict[str, str]]:
    """
    Combine plusieurs sources passives et remonte aussi un statut par source.

    Retourne (subdomains, errors) :
      - subdomains : set[str]
      - errors     : dict[source_name -> error_code]
                     ex: {"bufferover": "network_error"}
    """
    all_names: set[str] = set()
    errors: dict[str, str] = {}

    # 1) CertSpotter (on garde la fonction telle quelle)
    try:
        cs_subs = certspotter(domain)
        if cs_subs:
            logger.info("[passive] certspotter -> %d sous-domaines", len(cs_subs))
        all_names.update(cs_subs)
    except Exception as e:
        logger.debug("CertSpotter error for %s: %s", domain, e)
        errors["certspotter"] = "error"

    # 2) BufferOver (safe)
    bo_subs, bo_err = bufferover_safe(domain)
    if bo_subs:
        logger.info("[passive] bufferover -> %d sous-domaines", len(bo_subs))
    all_names.update(bo_subs)
    if bo_err:
        errors["bufferover"] = bo_err

    # 3) HackerTarget (comme avant, mais catch global)
    try:
        ht_subs = hackertarget(domain)
        if ht_subs:
            logger.info("[passive] hackertarget -> %d sous-domaines", len(ht_subs))
        all_names.update(ht_subs)
    except Exception as e:
        logger.debug("HackerTarget error for %s: %s", domain, e)
        errors["hackertarget"] = "error"

    return _dedupe_filter(all_names, domain), errors
