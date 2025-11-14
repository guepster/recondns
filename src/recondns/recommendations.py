# src/recondns/recommendations.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List


@dataclass
class NextStepRule:
    id: str
    category: str        # ex: "dns", "mail", "cloud", "staging", "governance"
    team: str            # RED, BLUE, CLOUD, GOV, MAIL, DEV
    severity: str        # "info", "low", "medium", "high"
    text: str            # message affiché à l'utilisateur
    condition: Callable[[Dict[str, Any]], bool]


NEXT_STEP_RULES: List[NextStepRule] = []


# Mapping catégorie -> team par défaut
CATEGORY_DEFAULT_TEAMS: Dict[str, str] = {
    "dns": "BLUE",
    "mail": "MAIL",
    "cloud": "CLOUD",
    "subdomains": "RED",
    "staging": "DEV",
    "takeover": "RED",
    "passive": "BLUE",
    "governance": "GOV",
    "risk": "GOV",
}


def _register_rule(
    id: str,
    category: str,
    severity: str,
    text: str,
    condition: Callable[[Dict[str, Any]], bool],
    team: str | None = None,
) -> None:
    """
    Helper pour ajouter une règle dans la bibliothèque.
    Si `team` n'est pas précisé, on dérive depuis la catégorie.
    """
    if team is None:
        team = CATEGORY_DEFAULT_TEAMS.get(category, "GOV")

    NEXT_STEP_RULES.append(
        NextStepRule(
            id=id,
            category=category,
            team=team,
            severity=severity,
            text=text,
            condition=condition,
        )
    )


# =======================
# RULE ENGINE
# =======================

def build_next_steps(report: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Applique toutes les règles et retourne un dict par team:
    {
      "RED": [ "…", ...],
      "BLUE": [...],
      ...
    }
    """
    buckets: Dict[str, List[str]] = {
        "RED": [],
        "BLUE": [],
        "CLOUD": [],
        "MAIL": [],
        "DEV": [],
        "GOV": [],
    }

    for rule in NEXT_STEP_RULES:
        try:
            if rule.condition(report):
                buckets[rule.team].append(rule.text)
        except Exception:
            # sécurité : une règle ne doit jamais casser l'outil
            continue

    return buckets


# -----------------------
# Helpers sur le report
# -----------------------

def _get_dns(report: Dict[str, Any]) -> Dict[str, List[str]]:
    return report.get("dns") or {}


def _get_mail(report: Dict[str, Any]) -> Dict[str, Any]:
    return report.get("mail_security") or {}


def _get_ip_enrichment(report: Dict[str, Any]) -> Dict[str, Any]:
    return report.get("ip_enrichment") or {}


def _get_takeovers(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    return report.get("takeover_checks") or []


def _get_all_subdomains(report: Dict[str, Any]) -> List[str]:
    crt = report.get("crt_subdomains") or []
    passive = report.get("passive_subdomains") or []
    resolved = (report.get("crt_subdomains_resolved") or {}).keys()
    subs = set()
    for s in crt:
        if isinstance(s, str):
            subs.add(s.lower())
    for s in passive:
        if isinstance(s, str):
            subs.add(s.lower())
    for s in resolved:
        if isinstance(s, str):
            subs.add(s.lower())
    return sorted(subs)


def _match_subdomains(report: Dict[str, Any], patterns: List[str]) -> List[str]:
    subs = _get_all_subdomains(report)
    hits: List[str] = []
    for s in subs:
        if any(p in s for p in patterns):
            hits.append(s)
    return hits


def _has_cloud(report: Dict[str, Any], name: str) -> bool:
    ip_enrich = _get_ip_enrichment(report)
    for info in ip_enrich.values():
        cloud = str(info.get("cloud") or "").lower()
        if name.lower() in cloud:
            return True
    return False


def _countries(report: Dict[str, Any]) -> List[str]:
    ip_enrich = _get_ip_enrichment(report)
    countries = {
        str(info.get("country") or "").strip()
        for info in ip_enrich.values()
        if info.get("country")
    }
    return sorted(c for c in countries if c)


def _clouds(report: Dict[str, Any]) -> List[str]:
    ip_enrich = _get_ip_enrichment(report)
    clouds = {
        str(info.get("cloud") or "").strip()
        for info in ip_enrich.values()
        if info.get("cloud")
    }
    return sorted(c for c in clouds if c and c != "-")


def _unique_asns(report: Dict[str, Any]) -> List[str]:
    ip_enrich = _get_ip_enrichment(report)
    asns = {
        str(info.get("asn") or "").strip()
        for info in ip_enrich.values()
        if info.get("asn")
    }
    return sorted(a for a in asns if a)


def _has_mx_provider(report: Dict[str, Any], keyword: str) -> bool:
    mail = _get_mail(report)
    hosts = mail.get("mx_hosts") or []
    for h in hosts:
        if keyword.lower() in str(h).lower():
            return True
    return False


def _passive_errors(report: Dict[str, Any]) -> Dict[str, str]:
    return report.get("passive_errors") or {}


# ===========================
#  RÈGLES DNS / SURFACE
# ===========================

_register_rule(
    id="dns_no_subdomains",
    category="dns",
    severity="info",
    text="Aucun sous-domaine détecté : vérifier que le domaine est réellement inactif ou garé.",
    condition=lambda r: len(_get_all_subdomains(r)) == 0,
)

_register_rule(
    id="dns_very_small_surface",
    category="dns",
    severity="info",
    text="Surface DNS très limitée : mettre en place des alertes en cas de création de nouveaux sous-domaines.",
    condition=lambda r: 0 < len(_get_all_subdomains(r)) <= 5,
)

_register_rule(
    id="dns_small_surface",
    category="dns",
    severity="low",
    text="Surface DNS modérée : conserver un inventaire à jour des sous-domaines exposés.",
    condition=lambda r: 6 <= len(_get_all_subdomains(r)) <= 20,
)

_register_rule(
    id="dns_large_surface",
    category="dns",
    severity="medium",
    text="Surface DNS importante : prioriser un inventaire formel des sous-domaines et une revue régulière.",
    condition=lambda r: 21 <= len(_get_all_subdomains(r)) <= 100,
)

_register_rule(
    id="dns_very_large_surface",
    category="dns",
    severity="high",
    text="Surface DNS massive : envisager de réduire le nombre de sous-domaines publics ou de les regrouper derrière des reverse-proxy/WAF.",
    condition=lambda r: len(_get_all_subdomains(r)) > 100,
)

_register_rule(
    id="dns_no_ipv6",
    category="dns",
    severity="low",
    text="Aucun enregistrement AAAA : décider explicitement si IPv6 doit être supporté ou non sur ce domaine.",
    condition=lambda r: len(_get_dns(r).get("AAAA", []) or []) == 0,
)

_register_rule(
    id="dns_has_ipv6",
    category="dns",
    severity="info",
    text="IPv6 présent : vérifier que les politiques de sécurité sont cohérentes entre IPv4 et IPv6 (FW/WAF/logs).",
    condition=lambda r: len(_get_dns(r).get("AAAA", []) or []) > 0,
)

_register_rule(
    id="dns_many_ns",
    category="dns",
    severity="low",
    text="Plusieurs serveurs NS : s’assurer que la configuration DNS est cohérente et bien répliquée.",
    condition=lambda r: len(_get_dns(r).get("NS", []) or []) >= 4,
)

_register_rule(
    id="dns_single_ns",
    category="dns",
    severity="medium",
    text="Un seul NS détecté : risque de SPOF DNS, envisager au moins un second serveur DNS.",
    condition=lambda r: len(_get_dns(r).get("NS", []) or []) == 1,
)

_register_rule(
    id="dns_no_mx",
    category="dns",
    severity="low",
    text="Aucun MX trouvé : vérifier que le domaine n’est pas utilisé pour l’envoi/réception d’e-mails.",
    condition=lambda r: len(_get_dns(r).get("MX", []) or []) == 0,
)

_register_rule(
    id="dns_multiple_mx",
    category="dns",
    severity="info",
    text="Plusieurs MX : vérifier qu’ils sont correctement priorisés et maintenus.",
    condition=lambda r: len(_get_dns(r).get("MX", []) or []) >= 2,
)

# ===========================
#  RÈGLES MAIL / SPF / DMARC / DKIM
# ===========================

_register_rule(
    id="mail_no_spf",
    category="mail",
    severity="high",
    text="SPF absent : forte exposition au spoofing, définir un enregistrement SPF pour le domaine.",
    condition=lambda r: not _get_mail(r).get("has_spf", False),
)

_register_rule(
    id="mail_no_dmarc",
    category="mail",
    severity="high",
    text="DMARC absent : implémenter DMARC avec une politique progressive (p=none → quarantine → reject).",
    condition=lambda r: not _get_mail(r).get("has_dmarc", False),
)

_register_rule(
    id="mail_no_dkim",
    category="mail",
    severity="medium",
    text="DKIM non détecté : signer les e-mails avec DKIM pour renforcer l’authentivité et la délivrabilité.",
    condition=lambda r: not _get_mail(r).get("has_dkim_hint", False),
)

_register_rule(
    id="mail_full_stack_ok",
    category="mail",
    severity="info",
    text="SPF + DMARC configurés : surveiller les rapports DMARC pour détecter d’éventuels envois non autorisés.",
    condition=lambda r: _get_mail(r).get("has_spf", False)
    and _get_mail(r).get("has_dmarc", False),
)

_register_rule(
    id="mail_spf_only",
    category="mail",
    severity="medium",
    text="SPF présent mais DMARC absent : ajouter DMARC pour compléter la protection contre le spoofing.",
    condition=lambda r: _get_mail(r).get("has_spf", False)
    and not _get_mail(r).get("has_dmarc", False),
)

_register_rule(
    id="mail_dmarc_only",
    category="mail",
    severity="medium",
    text="DMARC déclaré sans SPF : configurer SPF pour renforcer la cohérence des politiques d’envoi.",
    condition=lambda r: not _get_mail(r).get("has_spf", False)
    and _get_mail(r).get("has_dmarc", False),
)

_register_rule(
    id="mail_o365_provider",
    category="mail",
    severity="info",
    text="MX O365 : vérifier les paramètres de sécurité EOP/Defender (anti-spam, anti-phishing, auth).",
    condition=lambda r: _has_mx_provider(r, "protection.outlook.com"),
)

_register_rule(
    id="mail_google_workspace",
    category="mail",
    severity="info",
    text="MX Google : s’assurer que les règles de sécurité Google Workspace sont alignées avec la politique globale.",
    condition=lambda r: _has_mx_provider(r, "google.com"),
)

_register_rule(
    id="mail_multiple_providers",
    category="mail",
    severity="medium",
    text="Plusieurs providers MX détectés : clarifier quels services sont légitimes pour l’envoi d’e-mails.",
    condition=lambda r: len(set((_get_mail(r).get("mx_hosts") or []))) >= 2,
)

# ===========================
#  RÈGLES CLOUD / HÉBERGEMENT
# ===========================

_register_rule(
    id="cloud_multi_country",
    category="cloud",
    severity="medium",
    text="Hébergement multi-pays : vérifier l’adéquation avec les contraintes légales (RGPD, localisation des données).",
    condition=lambda r: len(_countries(r)) >= 2,
)

_register_rule(
    id="cloud_single_country",
    category="cloud",
    severity="info",
    text="Hébergement concentré dans un seul pays : documenter le choix et l’impact en termes de résilience et de conformité.",
    condition=lambda r: len(_countries(r)) == 1,
)

_register_rule(
    id="cloud_multi_cloud",
    category="cloud",
    severity="medium",
    text="Multiples clouds publics détectés : cartographier les environnements (AWS/Azure/GCP/OVH…) et les flux entre eux.",
    condition=lambda r: len(_clouds(r)) >= 2,
)

_register_rule(
    id="cloud_single_cloud",
    category="cloud",
    severity="info",
    text="Cloud unique dominant : formaliser les bonnes pratiques (guardrails, blueprints, policies) pour ce provider.",
    condition=lambda r: len(_clouds(r)) == 1,
)

_register_rule(
    id="cloud_aws_present",
    category="cloud",
    severity="info",
    text="AWS détecté : vérifier la configuration des Security Groups, NACL et du WAF sur les hôtes exposés.",
    condition=lambda r: _has_cloud(r, "aws"),
)

_register_rule(
    id="cloud_azure_present",
    category="cloud",
    severity="info",
    text="Azure détecté : s’assurer de la bonne configuration NSG / Front Door / Application Gateway sur les endpoints publics.",
    condition=lambda r: _has_cloud(r, "azure"),
)

_register_rule(
    id="cloud_gcp_present",
    category="cloud",
    severity="info",
    text="GCP détecté : vérifier les règles de firewall VPC, les load balancers et les ACLs sur les services exposés.",
    condition=lambda r: _has_cloud(r, "gcp"),
)

_register_rule(
    id="cloud_ovh_present",
    category="cloud",
    severity="info",
    text="OVH détecté : vérifier la configuration des reverse-proxy/anti-DDoS et la segmentation réseau des VMs exposées.",
    condition=lambda r: _has_cloud(r, "ovh"),
)

_register_rule(
    id="cloud_many_asn",
    category="cloud",
    severity="medium",
    text="Multiples ASNs détectés : documenter les différents prestataires d’hébergement et leurs responsables internes.",
    condition=lambda r: len(_unique_asns(r)) >= 3,
)

# ===========================
#  RÈGLES SUBDOMAINS SENSIBLES
# ===========================

_register_rule(
    id="sub_admin",
    category="subdomains",
    severity="high",
    text="Sous-domaines administratifs détectés : restreindre l’accès (VPN, IP whitelisting, MFA obligatoire).",
    condition=lambda r: len(_match_subdomains(r, ["admin", "administrator", "panel"])) > 0,
)

_register_rule(
    id="sub_login_portal",
    category="subdomains",
    severity="medium",
    text="Portails de connexion détectés : appliquer MFA et vérifier la robustesse des politiques de mot de passe.",
    condition=lambda r: len(_match_subdomains(r, ["login", "portal", "sso"])) > 0,
)

_register_rule(
    id="sub_api",
    category="subdomains",
    severity="medium",
    text="APIs exposées : limiter l’accès, documenter les scopes d’authentification et éviter les secrets dans les URLs.",
    condition=lambda r: len(_match_subdomains(r, ["api.", "-api", "api-"])) > 0,
)

_register_rule(
    id="sub_vpn",
    category="subdomains",
    severity="high",
    text="Endpoints VPN détectés : s’assurer de la mise à jour régulière et de la robustesse de l’authentification.",
    condition=lambda r: len(_match_subdomains(r, ["vpn.", "ssl-vpn", "remote"])) > 0,
)

_register_rule(
    id="sub_intranet",
    category="subdomains",
    severity="medium",
    text="Sous-domaines intranet / internes visibles : vérifier s’ils doivent réellement être exposés sur Internet.",
    condition=lambda r: len(_match_subdomains(r, ["intranet", "internal", "int."])) > 0,
)

_register_rule(
    id="sub_git_ci_cd",
    category="subdomains",
    severity="high",
    text="Sous-domaines liés à Git/CI détectés (git, ci, jenkins…) : éviter l’exposition publique de ces outils.",
    condition=lambda r: len(_match_subdomains(r, ["git", "jenkins", "ci.", "teamcity"])) > 0,
)

_register_rule(
    id="sub_rdp_terminal",
    category="subdomains",
    severity="high",
    text="Sous-domaines évoquant un accès distant (rdp, terminal…) : vérifier qu’aucun service RDP n’est directement exposé.",
    condition=lambda r: len(_match_subdomains(r, ["rdp", "terminal", "desktop"])) > 0,
)

_register_rule(
    id="sub_mail_webmail",
    category="subdomains",
    severity="medium",
    text="Webmail détecté : protéger l’accès avec MFA, limitations d’IP ou captchas selon le contexte.",
    condition=lambda r: len(_match_subdomains(r, ["webmail", "mail."])) > 0,
)

_register_rule(
    id="sub_files_storage",
    category="subdomains",
    severity="medium",
    text="Sous-domaines de partage de fichiers détectés : vérifier les permissions par défaut et les liens publics.",
    condition=lambda r: len(_match_subdomains(r, ["files", "share", "storage"])) > 0,
)

# ===========================
#  RÈGLES DEV / STAGING / TEST
# ===========================

_register_rule(
    id="env_staging_detected",
    category="staging",
    severity="medium",
    text="Environnements de staging/test détectés : limiter leur exposition publique et éviter les données réelles.",
    condition=lambda r: len(_match_subdomains(r, ["staging", "test.", "preprod", "recette"])) > 0,
)

_register_rule(
    id="env_many_staging_hosts",
    category="staging",
    severity="medium",
    text="Plusieurs sous-domaines non-prod (staging/dev) : aligner leurs patchs sécurité avec la production.",
    condition=lambda r: len(_match_subdomains(r, ["staging", "dev.", "preprod"])) >= 3,
)

_register_rule(
    id="env_dev_internet_exposed",
    category="staging",
    severity="high",
    text="Environnements de développement accessibles sur Internet : les restreindre au maximum (VPN, IP filtrées).",
    condition=lambda r: len(_match_subdomains(r, ["dev.", ".dev."])) > 0,
)

_register_rule(
    id="env_demo_beta",
    category="staging",
    severity="low",
    text="Environnements demo/beta détectés : vérifier qu’ils ne contiennent pas de données sensibles ou de fonctionnalités non stabilisées.",
    condition=lambda r: len(_match_subdomains(r, ["demo", "beta"])) > 0,
)

# ===========================
#  RÈGLES TAKEOVER
# ===========================

_register_rule(
    id="takeover_findings",
    category="takeover",
    severity="high",
    text="Potentiels Subdomain Takeover détectés : supprimer ou corriger les enregistrements CNAME orphelins.",
    condition=lambda r: len(_get_takeovers(r)) > 0,
)

_register_rule(
    id="takeover_none_but_many_subs",
    category="takeover",
    severity="info",
    text="Aucun takeover détecté : conserver un monitoring périodique, surtout en cas de nombreux CNAME vers des SaaS.",
    condition=lambda r: len(_get_takeovers(r)) == 0 and len(_get_all_subdomains(r)) > 20,
)

# ===========================
#  RÈGLES SOURCES PASSIVES
# ===========================

_register_rule(
    id="passive_errors_present",
    category="passive",
    severity="low",
    text="Certaines sources passives ont échoué : compléter l’analyse par d’autres outils (amass, subfinder, etc.).",
    condition=lambda r: bool(_passive_errors(r)),
)

_register_rule(
    id="passive_bufferover_error",
    category="passive",
    severity="info",
    text="BufferOver indisponible : relancer un scan plus tard ou compléter avec d’autres sources OSINT.",
    condition=lambda r: "bufferover" in _passive_errors(r),
)

_register_rule(
    id="passive_only_few_sources",
    category="passive",
    severity="info",
    text="Peu de sous-domaines passifs détectés : envisager d’ajouter d’autres sources OSINT si le scope est critique.",
    condition=lambda r: len(r.get("passive_subdomains") or []) <= 3,
)

# ===========================
#  RÈGLES MONITORING / PROCESS
# ===========================

_register_rule(
    id="monitoring_snapshot_regular",
    category="governance",
    severity="info",
    text="Mettre en place des snapshots réguliers (`snapshot`) et comparer dans le temps (`diff`) pour suivre l’évolution de la surface DNS.",
    condition=lambda r: True,
)

_register_rule(
    id="monitoring_export_ips",
    category="governance",
    severity="medium",
    text="Exporter les IPs découvertes vers le SIEM ou l’outil de vulnérabilités pour les intégrer au scope de scan.",
    condition=lambda r: len(_get_ip_enrichment(r)) > 0,
)

_register_rule(
    id="monitoring_high_subdomains",
    category="governance",
    severity="medium",
    text="Surface DNS importante : mettre en place des alertes sur création/modification de DNS (API registrar ou DNS monitoring).",
    condition=lambda r: len(_get_all_subdomains(r)) > 30,
)

_register_rule(
    id="monitoring_few_assets",
    category="governance",
    severity="low",
    text="Peu d’actifs détectés : valider auprès des équipes métiers que la cartographie est complète (aucun domaine oublié).",
    condition=lambda r: 0 < len(_get_all_subdomains(r)) <= 10,
)

_register_rule(
    id="monitoring_many_ips",
    category="governance",
    severity="medium",
    text="Nombre d’IP exposées significatif : aligner ces IPs avec un inventaire CMDB et un responsable pour chaque service.",
    condition=lambda r: len(_get_ip_enrichment(r)) >= 10,
)

_register_rule(
    id="monitoring_single_ip",
    category="governance",
    severity="info",
    text="Une seule IP exposée : vérifier si d’autres services se cachent derrière (reverse-proxy, virtual hosts).",
    condition=lambda r: len(_get_ip_enrichment(r)) == 1,
)

# ===========================
#  RÈGLES DIVERS / RISK
# ===========================

_register_rule(
    id="risk_multi_cloud_multi_country",
    category="risk",
    severity="high",
    text="Multi-cloud + multi-pays : formaliser une stratégie de gouvernance centralisée (sécurité, logs, conformité) pour éviter les angles morts.",
    condition=lambda r: len(_clouds(r)) >= 2 and len(_countries(r)) >= 2,
)

_register_rule(
    id="risk_email_spoofing_total",
    category="risk",
    severity="high",
    text="Absence totale de SPF/DMARC/DKIM : domaine très exposé au spoofing, à traiter en priorité.",
    condition=lambda r: not _get_mail(r).get("has_spf", False)
    and not _get_mail(r).get("has_dmarc", False)
    and not _get_mail(r).get("has_dkim_hint", False),
)

_register_rule(
    id="risk_many_staging_and_apis",
    category="risk",
    severity="high",
    text="Beaucoup d’environnements non-prod et d’APIs exposés : prioriser une revue de surface sur ces hôtes.",
    condition=lambda r: len(_match_subdomains(r, ["staging", "test.", "dev."])) >= 3
    and len(_match_subdomains(r, ["api.", "-api", "api-"])) >= 2,
)

_register_rule(
    id="risk_sensitive_mail_and_admin",
    category="risk",
    severity="high",
    text="Sous-domaines admin + mail exposés : combiner durcissement des accès et surveillance renforcée sur ces points d’entrée.",
    condition=lambda r: len(_match_subdomains(r, ["admin", "panel"])) > 0
    and len(_match_subdomains(r, ["mail.", "webmail"])) > 0,
)
