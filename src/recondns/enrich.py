import logging

import requests

logger = logging.getLogger("recondns")

IPINFO_URL = "https://ipinfo.io/{ip}/json"

COMMON_CLOUDS = {
    "amazon": "AWS",
    "amazon.com": "AWS",
    "aws": "AWS",
    "amazonaws": "AWS",
    "google": "GCP",
    "google cloud": "GCP",
    "google llc": "GCP",
    "microsoft": "Azure",
    "azure": "Azure",
    "cloudflare": "Cloudflare",
    "ovh": "OVH",
    "hetzner": "Hetzner",
}


def detect_cloud(as_name: str) -> str:
    if not as_name:
        return "Unknown"
    lower = as_name.lower()
    for k, v in COMMON_CLOUDS.items():
        if k in lower:
            return v
    return "Other"


def enrich_ip(ip: str) -> dict:
    """Enrichit l'IP avec ASN, pays, provider cloud."""
    try:
        r = requests.get(IPINFO_URL.format(ip=ip), timeout=5)
        if r.status_code != 200:
            return {}

        data = r.json()
        asn = None
        as_name = None
        if "org" in data:
            parts = data["org"].split(" ", 1)
            if len(parts) == 2:
                asn = parts[0].replace("AS", "")
                as_name = parts[1]

        return {
            "asn": int(asn) if asn and asn.isdigit() else None,
            "as_name": as_name,
            "country": data.get("country"),
            "cloud_provider": detect_cloud(as_name or ""),
        }

    except Exception as e:
        logger.warning("Enrich IP failed for %s: %s", ip, e)
        return {}
