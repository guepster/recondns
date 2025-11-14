import json
from datetime import datetime


def save_json(obj, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def load_json(path):
    import json

    with open(path, encoding="utf-8") as f:
        return json.load(f)


def make_snapshot_filename(domain):
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    return f"{domain}_snapshot_{ts}.json"

def build_next_steps(report: dict) -> list[str]:
    steps = []

    subdomains = report.get("crt_subdomains", []) or []
    ips = report.get("ip_enrichment", {}) or {}
    mail = report.get("mail_security", {}) or {}

    # 1) DKIM manquant
    if not mail.get("has_dkim_hint"):
        steps.append("Mettre en place DKIM et vérifier l’alignement SPF/DKIM/DMARC.")

    # 2) DMARC absent
    if not mail.get("has_dmarc"):
        steps.append("Activer DMARC pour renforcer la protection anti-spoofing.")

    # 3) SPF absent
    if not mail.get("has_spf"):
        steps.append("Créer une politique SPF correcte sur le domaine racine.")

    # 4) Multi-cloud ?
    clouds = {v.get("cloud") for v in ips.values() if v.get("cloud")}
    if len(clouds) >= 2:
        steps.append("Vérifier la cohérence de l’architecture multi-cloud et les flux entre environnements.")

    # 5) Multi-pays ?
    countries = {v.get("country") for v in ips.values() if v.get("country")}
    if len(countries) >= 2:
        steps.append("Vérifier les obligations légales/compliance liées à l'hébergement multi-pays.")

    # 6) Staging/dev/test détectés
    if any(s for s in subdomains if any(x in s for x in ("staging", "dev", "test", "recette"))):
        steps.append("Isoler ou protéger les environnements non-productifs (staging/test/dev).")

    # 7) Beaucoup de sous-domaines
    if len(subdomains) > 30:
        steps.append("Mettre en place un inventaire/monitoring des sous-domaines (DNS surface monitoring).")

    # 8) Beaucoup d’IP uniques (complexité surface)
    if len(ips) > 10:
        steps.append("Rationaliser ou analyser la diversité des IPs exposées pour réduire la surface d’attaque.")

    # 9) Takeover
    if report.get("takeover_checks"):
        steps.append("Corriger les CNAME orphelins ou configurations vulnérables (risque de takeover).")

    # 10) Domaine sans A records
    dns = report.get("dns", {})
    if not dns.get("A"):
        steps.append("Le domaine ne résout pas d’IP : vérifier les enregistrements DNS/NS.")

    # Toujours proposer un scan HTTP
    steps.append("Lancer un scan HTTP/HTTPS ciblé (bannières, titres, services exposés).")

    return steps
