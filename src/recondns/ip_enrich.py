# src/recondns/ip_enrich.py
import logging
from typing import Dict, Any, Optional, List

import requests

logger = logging.getLogger("recondns")

IPAPI_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,as,org,isp,query"


def _detect_cloud(asn: str, org: str, isp: str) -> Optional[str]:
    """
    Devine vaguement le cloud provider à partir de l'ASN / org / ISP.
    C'est heuristique, mais suffisant pour un rapport de recon.
    """
    combo = " ".join(filter(None, [asn, org, isp])).lower()

    if "amazon" in combo or "aws" in combo:
        return "AWS"
    if "google" in combo or "gcp" in combo:
        return "GCP"
    if "microsoft" in combo or "azure" in combo:
        return "Azure"
    if "cloudflare" in combo:
        return "Cloudflare"
    if "ovh" in combo:
        return "OVH"
    if "hetzner" in combo:
        return "Hetzner"
    if "digitalocean" in combo:
        return "DigitalOcean"
    return None


def enrich_ip(ip: str, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    """
    Interroge ip-api.com pour récupérer ASN / org / pays / etc.
    Retourne un petit dict prêt à être mis dans le rapport, ou None si échec.
    """
    url = IPAPI_URL.format(ip=ip)
    try:
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        data = r.json()

        if data.get("status") != "success":
            logger.debug("IP enrichment failed for %s: %s", ip, data.get("message"))
            return None

        asn = data.get("as") or ""
        org = data.get("org") or data.get("isp") or ""
        country = data.get("countryCode") or data.get("country") or ""
        cloud = _detect_cloud(asn, org, data.get("isp") or "")

        return {
            "ip": data.get("query") or ip,
            "asn": asn,
            "org": org,
            "country": country,
            "cloud": cloud,
        }
    except Exception as e:
        logger.debug("IP enrichment error for %s: %s", ip, e)
        return None


def enrich_many(ips: List[str], timeout: float = 5.0) -> Dict[str, Dict[str, Any]]:
    """
    Enrichit une liste d'IPs (sans doublons) et retourne un dict {ip: info}.
    """
    out: Dict[str, Dict[str, Any]] = {}
    seen = set()

    for ip in ips:
        ip = str(ip).strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)

        info = enrich_ip(ip, timeout=timeout)
        if info:
            out[ip] = info

    return out
