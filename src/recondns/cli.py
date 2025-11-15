# --- CLI / logging
import logging
from pathlib import Path
import click

from .recommendations import build_next_steps

# Optionnel mais conseillé sous Windows
try:
    import colorama

    colorama.init()
except ImportError:
    pass

# --- Helpers pour le rendu CLI (couleurs / titres) ---
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"


def title(text: str) -> str:
    """Titre de section en bleu clair et gras."""
    return click.style(text, fg="bright_blue", bold=True)


def ok(text: str) -> str:
    return click.style(text, fg="green")


def warn(text: str) -> str:
    return click.style(text, fg="yellow")


def bad(text: str) -> str:
    return click.style(text, fg="red")


# --- Helpers d'analyse avancée ---


def categorize_subdomain(name: str) -> list[str]:
    """
    Retourne une liste de tags pour un sous-domaine.
    Ex: ["dev"], ["admin", "api"], ["prod"], etc.
    """
    n = name.lower()

    tags: list[str] = []

    # --- environnements non-prod / sensibles pour tests ---
    dev_keywords = [
        "dev.",
        ".dev.",
        "-dev.",
        "test.",
        ".test.",
        "-test.",
        "recette.",
        ".recette.",
        "-recette.",
        "preprod.",
        ".preprod.",
        "-preprod.",
        "staging.",
        ".staging.",
        "-staging.",
        "sandbox.",
        ".sandbox.",
        "-sandbox.",
        "beta.",
        ".beta.",
        "-beta.",
    ]
    if any(k in n for k in dev_keywords):
        tags.append("dev")

    # --- endpoints sensibles "métier" / sécurité ---
    if any(x in n.split(".")[0] for x in ["admin", "panel", "backoffice", "back-office"]):
        tags.append("admin")
    if any(x in n for x in ["api.", ".api."]):
        tags.append("api")
    if any(x in n for x in ["auth.", "login.", "sso.", "idp."]):
        tags.append("auth")
    if any(x in n for x in ["vpn.", "remote.", "rdp.", "gateway."]):
        tags.append("remote")

    # Tu peux rajouter d’autres patterns plus tard

    return tags


0


def compute_risk_score(
    total_subdomains: int, clouds: list[str], mail_sec: dict | None, takeover_count: int
) -> tuple[int, str]:
    """
    Score très simple 0–100 + niveau (Low/Medium/High).
    Pas scientifique, juste cohérent et lisible.
    """
    score = 100

    # Surface DNS
    if total_subdomains > 200:
        score -= 30
    elif total_subdomains > 50:
        score -= 20
    elif total_subdomains > 10:
        score -= 10

    # Clouds publics
    if len(clouds) > 2:
        score -= 15
    elif len(clouds) == 2:
        score -= 8
    elif len(clouds) == 1:
        score -= 3  # un seul cloud, complexité moindre

    # Mail
    if mail_sec:
        if not mail_sec.get("has_spf"):
            score -= 10
        if not mail_sec.get("has_dmarc"):
            score -= 10
        if not mail_sec.get("has_dkim_hint"):
            score -= 5
    else:
        score -= 10  # aucune info mail -> on pénalise un peu

    # Takeover potentiels
    if takeover_count > 0:
        score -= 20

    if score >= 80:
        level = "Low"
    elif score >= 50:
        level = "Medium"
    else:
        level = "High"

    return max(score, 0), level


from .core import snapshot_domain
from .db import (
    get_snapshot_by_id,
    init_db,
)
from .db import (
    list_snapshots as db_list_snapshots,
)
from .db import (
    save_snapshot as db_save_snapshot,
)
from .diffs import diff_reports, diff_to_html
from .exporter import export_snapshot
from .report_md import render_diff_md
from .storage import (
    list_snapshots as fs_list_snapshots,
)
from .storage import (
    load_snapshot as fs_load_snapshot,
)

# --- MODE FICHIERS (snapshots JSON)
from .storage import (
    save_snapshot as fs_save_snapshot,
)


@click.version_option("0.1.0", prog_name="recondns")
@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx):
    """
    recondns – reconnaissance DNS + console interactive
    """
    if ctx.invoked_subcommand is None:
        from .interactive import start_console

        start_console()


@main.command()
def console():
    """
    Lance la console interactive RECONDNS.
    """
    from .interactive import start_console

    start_console()


# ---------- SNAPSHOT ----------
@main.command()
@click.argument("domain")
@click.option(
    "--out",
    "-o",
    default=None,
    help="Fichier de sortie JSON (si non précisé, nom auto dans ./data/).",
)
@click.option(
    "--no-crt", is_flag=True, default=False, help="Désactive l'appel vers crt.sh (rapide & safe)"
)
@click.option(
    "--minimal",
    is_flag=True,
    default=False,
    help="Affiche un résumé minimal après le snapshot (DNS/mail/surface).",
)
@click.option("--resolver", "-r", default=None, help="IP d'un résolveur DNS (ex: 1.1.1.1)")
@click.option("--timeout", default=2.0, type=float, help="Timeout DNS en secondes")
@click.option("--retries", default=1, type=int, help="Nombre de retries DNS")
@click.option(
    "--resolve-limit",
    default=None,
    type=int,
    help="Limite le nb de sous-domaines à résoudre (ex: 50)",
)
@click.option(
    "--check-takeover",
    is_flag=True,
    default=False,
    help="Active la détection de Subdomain Takeover (lecture seule)",
)
@click.option(
    "--signatures", default=None, help="Chemin vers un YAML de signatures (override par défaut)"
)
@click.option(
    "--takeover-workers",
    default=8,
    type=int,
    help="Nombre de threads pour checks takeover (default 8)",
)
@click.option("--takeover-delay", default=0.2, type=float, help="Délai entre checks takeover (sec)")
@click.option(
    "--takeover-verbose", is_flag=True, default=False, help="Mode verbeux pour takeover (logs)"
)
@click.option("--wordlist", default=None, help="Wordlist pour bruteforce de sous-domaines")
@click.option(
    "--bruteforce-depth", default=1, type=int, help="Profondeur de bruteforce (par défaut 1)"
)
@click.option(
    "--db",
    default=None,
    help="Chemin SQLite pour enregistrer l'historique (ex: data/recondns.sqlite)",
)
@click.option(
    "--web-scan",
    is_flag=True,
    default=False,
    help="Scan HTTP/HTTPS basique sur le domaine et les sous-domaines résolus.",
)
def snapshot(
    domain,
    out,
    no_crt,
    minimal,
    resolver,
    timeout,
    retries,
    resolve_limit,
    check_takeover,
    signatures,
    takeover_workers,
    takeover_delay,
    takeover_verbose,
    wordlist,
    bruteforce_depth,
    db,
    web_scan,
):
    """
    Prend un snapshot complet (DNS + passif + bruteforce + takeover) pour DOMAIN.

    - Écrit un JSON (local) avec tous les détails
    - Optionnellement, enregistre aussi dans une DB SQLite (--db)
    """
    if takeover_verbose:
        logging.getLogger("recondns").setLevel(logging.DEBUG)

    click.echo(f"[ SNAPSHOT ] Target: {domain}")
    click.echo("  ↳ collecte en cours...")

    report = snapshot_domain(
        domain,
        use_crt=(not no_crt),
        resolver_ips=[resolver] if resolver else None,
        timeout=timeout,
        retries=retries,
        resolve_limit=resolve_limit,
        check_takeover=check_takeover,
        signatures_path=signatures,
        takeover_max_workers=takeover_workers,
        takeover_delay=takeover_delay,
        takeover_verbose=takeover_verbose,
        wordlist=wordlist,
        bruteforce_depth=bruteforce_depth,
        web_scan=web_scan,
    )

    # Sauvegarde JSON (fichiers)
    outfile = export_snapshot(report, out)
    click.echo(f"[+] Snapshot écrit : {outfile}")

    # Sauvegarde DB (optionnelle)
    if db:
        init_db(db)
        snap_id = db_save_snapshot(db, report)
        click.echo(f"[+] Snapshot sauvegardé en DB ({db}) avec id={snap_id}")

    # --- Résumé minimal optionnel (réutilise la logique de info --minimal) ---
    if minimal:
        dns = report.get("dns", {}) or {}
        mail_sec = report.get("mail_security") or {}
        crt_subs = report.get("crt_subdomains") or []
        subs_data = report.get("crt_subdomains_resolved") or {}
        ip_enrich = report.get("ip_enrichment") or {}

        passive_errors = report.get("passive_errors") or {}

        if passive_errors:
            click.echo(title("[ PASSIVE SOURCES ]"))

            crt_ok = "OK" if crt_subs else "no data"
            click.echo(f"  crt.sh       : {crt_ok}")

            buff_status = passive_errors.get("bufferover")
            if buff_status is None:
                click.echo("  Bufferover   : OK")
            elif buff_status == "network_error":
                click.echo("  Bufferover   : indisponible (erreur réseau)")
            elif buff_status == "http_error":
                click.echo("  Bufferover   : erreur HTTP côté API")
            elif buff_status == "parse_error":
                click.echo("  Bufferover   : réponse invalide (parse error)")
            else:
                click.echo(f"  Bufferover   : erreur ({buff_status})")

        total_subdomains = len(crt_subs)
        resolved_subdomains = len(subs_data)
        unique_ips = len(ip_enrich) if ip_enrich else len(set(dns.get("A", [])))

        click.echo("")
        click.echo(title("[ SUMMARY ]"))
        click.echo(f"  Domain   : {domain}")
        click.echo(
            f"  DNS      : A={len(dns.get('A', []))} "
            f"AAAA={len(dns.get('AAAA', []))} "
            f"MX={len(dns.get('MX', []))} "
            f"NS={len(dns.get('NS', []))} "
            f"TXT={len(dns.get('TXT', []))}"
        )

        spf = "OK" if mail_sec.get("has_spf") else "NO"
        dmarc = "OK" if mail_sec.get("has_dmarc") else "NO"
        dkim = "OK" if mail_sec.get("has_dkim_hint") else "-"

        click.echo(f"  Mail     : SPF={spf}  DMARC={dmarc}  DKIM={dkim}")
        click.echo(
            f"  Surface  : subs={total_subdomains}  resolved={resolved_subdomains}  ips={unique_ips}"
        )

    return


# -------INFO-------


@main.command()
@click.argument("domain")
@click.option(
    "--no-crt", is_flag=True, default=False, help="Désactive l'appel vers crt.sh (rapide & safe)"
)
@click.option("--resolver", "-r", default=None, help="IP d'un résolveur DNS (ex: 1.1.1.1)")
@click.option("--timeout", default=2.0, type=float, help="Timeout DNS en secondes")
@click.option("--retries", default=1, type=int, help="Nombre de retries DNS")
@click.option(
    "--resolve-limit",
    default=None,
    type=int,
    help="Limite le nb de sous-domaines à résoudre (ex: 50)",
)
@click.option(
    "--check-takeover",
    is_flag=True,
    default=False,
    help="Active la détection de Subdomain Takeover (lecture seule)",
)
@click.option(
    "--signatures", default=None, help="Chemin vers un YAML de signatures (override par défaut)"
)
@click.option(
    "--takeover-workers",
    default=8,
    type=int,
    help="Nombre de threads pour checks takeover (default 8)",
)
@click.option("--takeover-delay", default=0.2, type=float, help="Délai entre checks takeover (sec)")
@click.option(
    "--takeover-verbose", is_flag=True, default=False, help="Mode verbeux pour takeover (logs)"
)
@click.option("--wordlist", default=None, help="Wordlist pour bruteforce de sous-domaines")
@click.option(
    "--bruteforce-depth", default=1, type=int, help="Profondeur de bruteforce (par défaut 1)"
)
@click.option("--out", "outfile", help="Sauvegarde le rapport JSON dans un fichier")
@click.option(
    "--provider-filter",
    multiple=True,
    help=(
        "Filtre les résultats takeover par provider "
        "(ex: --provider-filter heroku --provider-filter s3)"
    ),
)
@click.option(
    "--minimal",
    is_flag=True,
    default=False,
    help="Affiche uniquement les informations essentielles (sortie simplifiée).",
)
@click.option(
    "--web-scan",
    is_flag=True,
    default=False,
    help="Scan HTTP/HTTPS basique sur le domaine et les sous-domaines résolus.",
)
def info(
    domain,
    no_crt,
    resolver,
    timeout,
    retries,
    resolve_limit,
    check_takeover,
    signatures,
    takeover_workers,
    takeover_delay,
    takeover_verbose,
    wordlist,
    bruteforce_depth,
    outfile,
    provider_filter,
    minimal,
    web_scan,
):
    """Affiche un résumé en console (A / NS / MX counts + découverte passive/bruteforce)."""

    # logs takeover verbeux
    if takeover_verbose:
        logging.getLogger("recondns").setLevel(logging.DEBUG)

    # --- Snapshot complet ---
    report = snapshot_domain(
        domain,
        use_crt=(not no_crt),
        resolver_ips=[resolver] if resolver else None,
        timeout=timeout,
        retries=retries,
        resolve_limit=resolve_limit,
        check_takeover=check_takeover,
        signatures_path=signatures,
        takeover_max_workers=takeover_workers,
        takeover_delay=takeover_delay,
        takeover_verbose=takeover_verbose,
        wordlist=wordlist,
        bruteforce_depth=bruteforce_depth,
        web_scan=web_scan,
    )

    # --- Extraction des données de base ---
    dns = report.get("dns", {}) or {}
    crt_subs = report.get("crt_subdomains") or []
    subs_data = report.get("crt_subdomains_resolved") or {}
    takeovers = report.get("takeover_checks") or []
    ip_enrich = report.get("ip_enrichment") or {}
    mail_sec = report.get("mail_security") or {}

    # --- Calculs surface globale ---
    total_subdomains = len(crt_subs)
    resolved_subdomains = len(subs_data)
    unique_ips = len(ip_enrich) if ip_enrich else len(set(dns.get("A", [])))
    countries = sorted({info.get("country") for info in ip_enrich.values() if info.get("country")})
    asns = sorted({info.get("asn") for info in ip_enrich.values() if info.get("asn")})
    clouds = sorted(
        {
            info.get("cloud")
            for info in ip_enrich.values()
            if info.get("cloud") and info.get("cloud") != "-"
        }
    )

    # --- Filtre provider pour takeover (si demandé) ---
    if provider_filter:
        wanted = {p.lower().strip() for p in provider_filter}
        takeovers = [t for t in takeovers if (t.get("provider") or "").lower() in wanted]

    # =========================
    #  MODE MINIMAL
    # =========================
    if minimal:
        click.echo(title("[ TARGET ]"))
        click.echo(f"  {domain}\n")

        # DNS résumé
        click.echo(title("[ DNS ]"))
        click.echo(
            f"  A: {len(dns.get('A', []))}    "
            f"AAAA: {len(dns.get('AAAA', []))}    "
            f"MX: {len(dns.get('MX', []))}    "
            f"NS: {len(dns.get('NS', []))}    "
            f"TXT: {len(dns.get('TXT', []))}"
        )
        click.echo("")

        # Mail résumé
        click.echo(title("[ MAIL ]"))
        spf = ok("OK") if mail_sec.get("has_spf") else bad("NO")
        dmarc = ok("OK") if mail_sec.get("has_dmarc") else bad("NO")
        dkim = ok("OK") if mail_sec.get("has_dkim_hint") else warn("-")

        click.echo(f"  SPF: {spf}   DMARC: {dmarc}   DKIM: {dkim}")
        click.echo("")

        # Surface
        click.echo(title("[ SURFACE ]"))
        click.echo(
            f"  Subdomains: {total_subdomains}   "
            f"Resolved: {resolved_subdomains}   "
            f"IPs: {unique_ips}"
        )
        click.echo("")

        # Export JSON éventuel
        if outfile:
            import json

            with open(outfile, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            click.echo(f"JSON écrit dans {outfile}")

        return

    # --- Filtre provider pour takeover (si demandé) ---
    if provider_filter:
        wanted = {p.lower().strip() for p in provider_filter}
        takeovers = [t for t in takeovers if (t.get("provider") or "").lower() in wanted]

    # --- Calculs pour la surface globale ---
    total_subdomains = len(crt_subs)
    resolved_subdomains = len(subs_data)
    unique_ips = len(ip_enrich) if ip_enrich else len(set(dns.get("A", [])))
    countries = sorted({info.get("country") for info in ip_enrich.values() if info.get("country")})
    asns = sorted({info.get("asn") for info in ip_enrich.values() if info.get("asn")})
    clouds = sorted(
        {
            info.get("cloud")
            for info in ip_enrich.values()
            if info.get("cloud") and info.get("cloud") != "-"
        }
    )

    # ---------- HEADER ----------
    click.echo(title("[ TARGET ]"))
    click.echo(f"  {domain}\n")

    # =========================
    #  SECTION : SURFACE SUMMARY
    # =========================
    click.echo(title("[ SURFACE SUMMARY ]"))
    click.echo(f"  Sous-domaines découverts    : {total_subdomains}")
    click.echo(f"  Sous-domaines résolus (A)   : {resolved_subdomains}")
    click.echo(f"  IP uniques                  : {unique_ips}")
    if asns:
        click.echo(f"  Fournisseurs (ASN)          : {', '.join(asns)}")
    if countries:
        click.echo(f"  Pays d'hébergement          : {', '.join(countries)}")
    if clouds:
        click.echo(f"  Clouds publics détectés     : {', '.join(clouds)}")
    else:
        click.echo("  Clouds publics détectés     : aucun (hébergement classique)")
    click.echo("")

    # ---------- DNS SUMMARY ----------
    click.echo(title("[ DNS SUMMARY ]"))
    for k, desc in [
        ("A", "IPv4"),
        ("AAAA", "IPv6"),
        ("NS", "Name Servers"),
        ("MX", "Mail exchangers"),
        ("TXT", "TXT"),
        ("CNAME", "Aliases"),
    ]:
        count = len(dns.get(k, []))
        click.echo(f"  {k:<5}: {count:<6} ({desc})")
    click.echo(f"  crt.sh sous-domaines : {len(report.get('crt_subdomains', []))}\n")

    # ---------- SOUS-DOMAINS ----------
    crt_subs = report.get("crt_subdomains") or []
    passive_subs = report.get("passive_subdomains") or []
    brute_subs = (report.get("bruteforce") or {}).get("found", []) or []

    all_subs = sorted(set(crt_subs + passive_subs + brute_subs))

    high_value: list[tuple[str, list[str]]] = []
    dev_envs: list[str] = []

    if all_subs:
        # On tague tous les sous-domaines
        for s in all_subs:
            tags = categorize_subdomain(s)
            if tags:
                if any(t in tags for t in ["admin", "auth", "api"]):
                    high_value.append((s, tags))
                if "dev" in tags:
                    dev_envs.append(s)

        # --- listing général ---
        click.echo(title("[ SUBDOMAINS ]"))

        click.echo(f"  Total : {len(all_subs)} sous-domaines")
        max_show = 40
        to_show = all_subs[:max_show]

        for s in to_show:
            click.echo(f"   • {s}")

        if len(all_subs) > max_show:
            click.echo(
                warn(f"   + {len(all_subs)-max_show} autres " "(utilise --out pour JSON complet)")
            )

        click.echo("")

        # ---------- PASSIVE SOURCES ----------
        passive_subs = report.get("passive_subdomains") or []
        passive_errors = report.get("passive_errors") or {}

        if passive_subs or passive_errors:
            click.echo(title("[ PASSIVE SOURCES ]"))
            click.echo(f"  Sous-domaines passifs uniques : {len(passive_subs)}")

            if passive_errors:
                click.echo("  Erreurs / limites sources :")
                for src, err in passive_errors.items():
                    # err peut être une string ou autre, on force en str
                    click.echo(f"    - {src}: {str(err)}")
            else:
                click.echo("  Erreurs / limites sources : aucune")

            click.echo("")

        # --- HIGH VALUE ---
        if high_value:
            click.echo(title("[ HIGH-VALUE SUBDOMAINS ]"))
            for s, tags in high_value[:25]:
                tag_txt = ", ".join(tags)
                click.echo(f"   • {s:<40} [{tag_txt}]")
            if len(high_value) > 25:
                click.echo(
                    warn(f"   + {len(high_value)-25} autres high-value " "(voir JSON complet).")
                )
            click.echo("")

        # --- DEV / RECETTE / TEST ---
        if dev_envs:
            click.echo(title("[ DEV / TEST / RECETTE ]"))
            for s in dev_envs[:25]:
                click.echo(f"   • {s}")
            if len(dev_envs) > 25:
                click.echo(
                    warn(f"   + {len(dev_envs)-25} autres environnements " "non-prod détectés.")
                )
            click.echo("")

    # ---------- TAKEOVER ----------
    takeovers = report.get("takeover_checks") or []

    # Filtre éventuel par provider
    if provider_filter:
        wanted = {p.lower().strip() for p in provider_filter}
        takeovers = [t for t in takeovers if (t.get("provider") or "").lower() in wanted]

    if check_takeover:
        click.echo(title("[ TAKEOVER CHECKS ]"))
        if takeovers:
            for t in takeovers:
                host = t.get("host")
                provider = t.get("provider") or "?"
                method = t.get("method") or "?"
                scheme = t.get("scheme") or "http"
                status = t.get("status")
                status_txt = f"{scheme.upper()} {status}" if status is not None else scheme.upper()
                click.echo(f"  • {host} -> {provider} ({method}) [{status_txt}]")
        else:
            click.echo("  Aucun résultat (ou filtré par provider).")
        click.echo("")

    # ---------- IP ENRICHMENT ----------
    ip_enrich = report.get("ip_enrichment") or {}
    if ip_enrich:
        click.echo(title("[ IP ENRICHMENT ]"))
        for ip, info in ip_enrich.items():
            asn = info.get("asn") or "-"
            org = info.get("org") or "-"
            country = info.get("country") or "-"
            cloud = info.get("cloud") or "-"
            if cloud and cloud != "-":
                cloud_txt = f"{cloud}"
            else:
                cloud_txt = "-"
            click.echo(f"  {ip}")
            click.echo(f"    ├─ Country : {country}")
            click.echo(f"    ├─ ASN     : {asn}")
            click.echo(f"    ├─ Org     : {org}")
            click.echo(f"    └─ Cloud   : {cloud_txt}")
        click.echo("")

    # ---------- PROVIDERS / HOSTING ----------
    if ip_enrich:
        # mapping (asn, org, cloud) -> {ips, subs}
        providers: dict[tuple[str, str, str], dict[str, set[str]]] = {}

        # 1) on initialise les providers avec les IPs
        for ip, info_ip in ip_enrich.items():
            asn = info_ip.get("asn") or "-"
            org = info_ip.get("org") or "-"
            cloud = info_ip.get("cloud") or "-"
            key = (asn, org, cloud)
            bucket = providers.setdefault(key, {"ips": set(), "subs": set()})
            bucket["ips"].add(ip)

        # 2) on tente de mapper les sous-domaines -> IPs via crt_subdomains_resolved
        for sub, recs in subs_data.items():
            # recs peut être dict ({"A": [...]}), liste d'IPs ou string
            if isinstance(recs, dict):
                ips_for_sub = recs.get("A") or []
            elif isinstance(recs, list):
                ips_for_sub = recs
            else:
                ips_for_sub = [recs]

            for ip in ips_for_sub:
                info_ip = ip_enrich.get(ip)
                if not info_ip:
                    continue
                asn = info_ip.get("asn") or "-"
                org = info_ip.get("org") or "-"
                cloud = info_ip.get("cloud") or "-"
                key = (asn, org, cloud)
                bucket = providers.setdefault(key, {"ips": set(), "subs": set()})
                bucket["ips"].add(ip)
                bucket["subs"].add(sub)

        if providers:
            click.echo(title("[ PROVIDERS / HOSTING ]"))
            for (asn, org, cloud), data in providers.items():
                label_parts = []
                if asn != "-":
                    label_parts.append(asn)
                if org != "-":
                    label_parts.append(org)
                if cloud != "-":
                    label_parts.append(cloud)
                label = " / ".join(label_parts) if label_parts else "(inconnu)"

                click.echo(f"  {label}")
                click.echo(f"    • IPs          : {len(data['ips'])}")
                if data["subs"]:
                    samples = sorted(data["subs"])
                    if len(samples) > 5:
                        samples = samples[:5] + ["..."]
                    click.echo(f"    • Subdomains   : {', '.join(samples)}")
                click.echo("")

    # ---------- WEB DETAILS ----------
    web_hosts = (report.get("web") or {}).get("hosts") or {}
    if web_hosts:
        click.echo(title("[ WEB DETAILS ]"))

        def score_host(item):
            host, data = item
            tags = categorize_subdomain(host)
            score = 0
            if "admin" in tags:
                score += 3
            if "login" in tags or "auth" in tags:
                score += 2
            if "staging" in tags or "dev" in tags:
                score += 1
            return (-score, host)  # tri desc sur score, puis alpha

        for host, data in sorted(web_hosts.items(), key=score_host):
            http = data.get("http") or {}
            status = http.get("status", "?")
            page_title = http.get("title") or ""
            tech = ", ".join(http.get("tech") or [])
            click.echo(f"  • {host} → {status} {page_title} ({tech})")
        click.echo("")

    # ---------- WEB SUMMARY ----------
    web = web_hosts
    if web:
        click.echo(title("[ WEB SUMMARY ]"))

        total_hosts = len(web)
        up_hosts = 0
        code_counts: dict[int, int] = {}
        tech_set: set[str] = set()
        open_80 = 0
        open_443 = 0

        # stats headers de sécu
        sec_counts = {
            "hsts": 0,
            "csp": 0,
            "xfo": 0,
            "xcto": 0,
            "refpol": 0,
            "ppol": 0,
        }

        admin_hosts = 0
        staging_hosts = 0

        for host, data in web.items():
            ports = data.get("ports") or {}
            if ports.get(80) == "open":
                open_80 += 1
            if ports.get(443) == "open":
                open_443 += 1

            http = data.get("http") or {}
            status = http.get("status")
            if isinstance(status, int):
                up_hosts += 1
                code_counts[status] = code_counts.get(status, 0) + 1

            for t in http.get("tech") or []:
                tech_set.add(t)

            # Headers de sécu
            sec = http.get("security_headers") or {}
            if sec.get("hsts"):
                sec_counts["hsts"] += 1
            if sec.get("content_security_policy"):
                sec_counts["csp"] += 1
            if sec.get("x_frame_options"):
                sec_counts["xfo"] += 1
            if sec.get("x_content_type_options"):
                sec_counts["xcto"] += 1
            if sec.get("referrer_policy"):
                sec_counts["refpol"] += 1
            if sec.get("permissions_policy"):
                sec_counts["ppol"] += 1

            # Vue fonctionnelle simple
            host_low = host.lower()
            if any(k in host_low for k in ["admin", "adm", "backoffice"]):
                admin_hosts += 1
            if any(k in host_low for k in ["staging", "preprod", "test"]):
                staging_hosts += 1

        click.echo(f"  Hosts testés HTTP(S) : {total_hosts}")
        click.echo(f"  Hosts répondant      : {up_hosts}")
        click.echo(f"  Port 80 ouvert sur   : {open_80} hôtes")
        click.echo(f"  Port 443 ouvert sur  : {open_443} hôtes")

        # Répartition HTTP/HTTPS
        http_only = 0
        https_only = 0
        both = 0
        for data in web.values():
            p = data.get("ports") or {}
            is80 = p.get(80) == "open"
            is443 = p.get(443) == "open"
            if is80 and is443:
                both += 1
            elif is80:
                http_only += 1
            elif is443:
                https_only += 1

        click.echo(f"  HTTP only            : {http_only} hôtes")
        click.echo(f"  HTTPS only           : {https_only} hôtes")
        click.echo(f"  HTTP + HTTPS         : {both} hôtes")

        # Petites stats headers de sécu
        click.echo(
            "  Security headers     : "
            f"HSTS({sec_counts['hsts']}), "
            f"CSP({sec_counts['csp']}), "
            f"XFO({sec_counts['xfo']}), "
            f"X-Content-Type-Options({sec_counts['xcto']}), "
            f"Referrer-Policy({sec_counts['refpol']}), "
            f"Permissions-Policy({sec_counts['ppol']})"
        )

        if code_counts:
            parts = [f"{code}×{count}" for code, count in sorted(code_counts.items())]
            click.echo(f"  Codes HTTP           : {', '.join(parts)}")

        if tech_set:
            click.echo(f"  Stacks détectées     : {', '.join(sorted(tech_set))}")

        click.echo("")
        click.echo("  Vue fonctionnelle :")
        click.echo(f"    • Hôtes admin     : {admin_hosts}")
        click.echo(f"    • Hôtes staging   : {staging_hosts}")
        click.echo("")
        # ➕ Résumé lisible
        if up_hosts:
            click.echo(
                f"  → {up_hosts}/{total_hosts} hôtes répondent en HTTPS avec "
                f"{', '.join(sorted(tech_set)) or 'stacks web diverses'}."
            )
            click.echo("")

    # ---------- MAIL SECURITY ----------
    mail_sec = report.get("mail_security") or {}
    click.echo(title("[ MAIL SECURITY ]"))
    mx_hosts = mail_sec.get("mx_hosts") or []
    if mx_hosts:
        click.echo(f"  MX hosts     : {', '.join(mx_hosts)}")
    else:
        click.echo("  MX hosts     : (aucun)")

    has_spf = mail_sec.get("has_spf")
    has_dmarc = mail_sec.get("has_dmarc")
    has_dkim = mail_sec.get("has_dkim_hint")

    click.echo(f"  SPF          : " f"{ok('✅ OK') if has_spf else bad('❌ absent')}")
    click.echo(f"  DMARC        : " f"{ok('✅ OK') if has_dmarc else bad('❌ absent')}")
    if has_dkim:
        click.echo(f"  DKIM (hint)  : " f"{warn('⚠ hint présent dans TXT (à confirmer)')}")
    else:
        click.echo(
            f"  DKIM (hint)  : " f"{warn('⚠ aucun hint détecté (peut quand même être configuré)')}"
        )
    click.echo("")

    # =========================
    #  SECTION : FINDINGS
    # =========================
    findings: list[str] = []

    # Surface DNS
    if total_subdomains <= 5:
        findings.append("✔ Surface DNS très limitée (peu de sous-domaines exposés).")
    elif total_subdomains <= 20:
        findings.append("✔ Surface DNS modérée (surface maîtrisable mais à surveiller).")
    else:
        findings.append(
            "⚠ Surface DNS large : prioriser l'inventaire & la réduction de la surface."
        )

    # IP / clouds / pays
    if countries and len(countries) > 1:
        findings.append("⚠ Hébergement multi-pays : vérifier les contraintes légales/compliance.")
    if clouds and len(clouds) > 1:
        findings.append(
            "⚠ Multiples clouds publics détectés : surface hybride potentiellement complexe."
        )
    elif clouds:
        findings.append("✔ Usage d'un cloud public unique (surface plus prévisible).")

    # Mail
    if has_spf and has_dmarc:
        findings.append("✔ Mail protégé par SPF + DMARC (bonne base anti-spoofing).")
    else:
        findings.append("⚠ SPF/DMARC incomplets : risque de spoofing significatif.")
    if not has_dkim:
        findings.append("⚠ DKIM non détecté : à prévoir pour renforcer l'authenticité des mails.")

    # Web / headers de sécurité
    if web_hosts:
        total_web = len(web_hosts)
        if total_web >= 3:
            hsts = csp = xfo = 0
            for data in web_hosts.values():
                http = (data or {}).get("http") or {}
                sec = http.get("security_headers") or {}
                if sec.get("hsts"):
                    hsts += 1
                if sec.get("content_security_policy"):
                    csp += 1
                if sec.get("x_frame_options"):
                    xfo += 1

            if hsts == 0:
                findings.append(
                    "⚠ Aucun HSTS détecté sur les frontaux web : activer Strict-Transport-Security pour forcer l'usage de HTTPS."
                )
            if csp == 0:
                findings.append(
                    "⚠ Aucune Content-Security-Policy détectée : définir des CSP pour réduire les risques de XSS et d'injections côté client."
                )
            if xfo == 0:
                findings.append(
                    "⚠ X-Frame-Options absent : risque potentiel de clickjacking si les pages peuvent être intégrées dans des iframes."
                )

    click.echo(title("[ FINDINGS ]"))
    for f in findings:
        click.echo(f"  • {f}")
    click.echo("")

    # =========================
    #  SECTION : NEXT STEPS
    # =========================
    steps_by_team = build_next_steps(report)

    for team, items in steps_by_team.items():
        if not items:
            continue
        click.echo(title(f"[ NEXT STEPS — {team} TEAM ]"))
        for s in items:
            click.echo(f"  • {s}")
        click.echo("")

    # ---------- RISK SCORE ----------
    score, level = compute_risk_score(
        total_subdomains=total_subdomains,
        clouds=clouds,
        mail_sec=mail_sec,
        takeover_count=len(takeovers),
    )
    click.echo("")
    click.echo(title("[ RISK SCORE ]"))
    click.echo(f"  Global score   : {score} / 100")
    click.echo(f"  Niveau         : {level}")
    click.echo("")

    # ---------- QUICK RISK VIEW ----------
    click.echo(title("[ QUICK RISK VIEW ]"))

    # On base l'exposition sur le nb de sous-domaines découverts
    if total_subdomains <= 5:
        exposure = "faible"
    elif total_subdomains <= 20:
        exposure = "moyenne"
    else:
        exposure = "élevée"

    click.echo(f"  • Surface DNS       : {exposure}")
    if has_spf and has_dmarc:
        click.echo(f"  • Posture mail      : {ok('bonne (SPF/DMARC présents)')}")
    elif has_spf or has_dmarc:
        click.echo(f"  • Posture mail      : {warn('partielle (SPF ou DMARC manquant)')}")
    else:
        click.echo(f"  • Posture mail      : {bad('faible (ni SPF ni DMARC détectés)')}")
    if not has_dkim:
        click.echo(f"  • DKIM              : {warn('à vérifier / configurer si besoin')}")
    click.echo("")

    # ---- Export JSON optionnel ----
    if outfile:
        import json

        with open(outfile, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        click.echo(f"JSON écrit dans {outfile}")


# ---------- HISTORY ----------
@main.command()
@click.argument("domain")
@click.option("--db", required=True, help="Chemin SQLite (ex: data/recondns.sqlite)")
@click.option("--limit", default=20, type=int, help="Nombre de snapshots à lister")
@click.option(
    "--md", "as_md", is_flag=True, default=False, help="Affiche/exports l'historique en Markdown"
)
@click.option(
    "--out", "out_md", default=None, help="Chemin d'un fichier .md pour écrire le résultat"
)
def history(domain, db, limit, as_md, out_md):
    """Liste les snapshots d'un DOMAIN sauvegardés dans la DB."""
    init_db(db)
    rows = db_list_snapshots(db, domain, limit)
    if not rows:
        click.echo("Aucun snapshot trouvé.")
        return

    # Mode texte classique (comportement actuel)
    if not as_md:
        click.echo(f"Snapshots pour {domain} (plus récents d'abord) :")
        for r in rows:
            click.echo(f" id={r['id']}  ts={r['ts']}")
        return

    # Mode Markdown
    lines = [
        f"# Historique des snapshots — {domain}",
        "",
        "| id | timestamp | domaine |",
        "|----|-----------|---------|",
    ]
    for r in rows:
        lines.append(f"| {r['id']} | {r['ts']} | {r['domain']} |")

    md_text = "\n".join(lines)

    if out_md:
        try:
            with open(out_md, "w", encoding="utf-8") as f:
                f.write(md_text)
            click.echo(f"[+] Historique Markdown écrit dans {out_md}")
        except OSError as e:
            click.echo(f"[!] Impossible d'écrire le fichier Markdown : {e}")
    else:
        click.echo(md_text)


# ---------- DIFF ----------
@main.command()
@click.argument("domain")
@click.option("--db", required=True, help="Chemin SQLite (ex: data/recondns.sqlite)")
@click.option("--from", "from_id", required=True, type=int, help="ID snapshot source")
@click.option("--to", "to_id", required=True, type=int, help="ID snapshot cible")
@click.option(
    "--html", "html_path", default=None, help="Écrit aussi un rapport HTML complet dans ce fichier"
)
def diff(domain, db, from_id, to_id, html_path):
    """Affiche les différences entre deux snapshots (IDs)."""
    init_db(db)
    a = get_snapshot_by_id(db, from_id)
    b = get_snapshot_by_id(db, to_id)
    if not a or not b:
        click.echo("Snapshots introuvables. Vérifie les IDs.")
        return
    if a.get("domain") != domain or b.get("domain") != domain:
        click.echo("Les snapshots ne correspondent pas au domaine demandé.")
        return

    d = diff_reports(a, b)

    click.echo(f"Diff {domain}  {d['meta']['from']}  →  {d['meta']['to']}")
    # DNS
    if d["dns"]:
        click.echo("\n[DNS]")
        for k, v in d["dns"].items():
            if v.get("added"):
                click.echo(f" {k} added:   {v['added']}")
            if v.get("removed"):
                click.echo(f" {k} removed: {v['removed']}")
    # CRT subs
    if d["crt_subdomains"]:
        click.echo("\n[CRT Subdomains]")
        ad = d["crt_subdomains"].get("added") or []
        rm = d["crt_subdomains"].get("removed") or []
        if ad:
            click.echo(f" added:   {ad[:50]}{' ...' if len(ad) > 50 else ''}")
        if rm:
            click.echo(f" removed: {rm[:50]}{' ...' if len(rm) > 50 else ''}")
    # Takeover
    if d["takeover"]:
        click.echo("\n[Takeover]")
        ad = d["takeover"].get("added") or []
        rm = d["takeover"].get("removed") or []
        if ad:
            click.echo(f" added:   {ad}")
        if rm:
            click.echo(f" removed: {rm}")
    if not d["dns"] and not d["crt_subdomains"] and not d["takeover"]:
        click.echo("Aucun changement détecté.")

    # Export HTML optionnel
    if html_path:
        html = diff_to_html(domain, d)
        try:
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html)
            click.echo(f"[+] Rapport HTML écrit dans {html_path}")
        except OSError as e:
            click.echo(f"[!] Impossible d'écrire le rapport HTML : {e}")


# ---------- TRACK (fichiers) ----------
@main.command("track")
@click.argument("domain")
@click.option("--resolve-limit", default=50, type=int)
@click.option("--check-takeover", is_flag=True, default=False)
@click.option("--label", default=None, help="suffixe du nom du fichier")
def cmd_track(domain, resolve_limit, check_takeover, label):
    """
    Scan + enregistre un snapshot JSON local: data/<domain>/YYYYmmdd_HHMMSS[_label].json
    """
    click.echo(f"[track] scan {domain} ...")
    report = snapshot_domain(
        domain,
        use_crt=True,
        resolver_ips=None,  # résolveur système
        timeout=2.0,
        retries=1,
        resolve_limit=resolve_limit,
        check_takeover=check_takeover,
        signatures_path=None,
        takeover_max_workers=8,
        takeover_delay=0.2,
        takeover_verbose=False,
        wordlist=None,
        bruteforce_depth=1,
    )

    path = fs_save_snapshot(domain, report, label=label)
    click.echo(f"[ok] snapshot -> {path}")


# ---------- TIMELINE (fichiers) ----------
@main.command("timeline")
@click.argument("domain")
def cmd_timeline(domain):
    """
    Liste les snapshots JSON locaux pour un domaine.
    """
    snaps = fs_list_snapshots(domain)
    if not snaps:
        click.echo("Aucun snapshot.")
        return
    for p in snaps:
        click.echo(p.name)


# ---------- DIFF-JSON (fichiers) ----------
@main.command("diff-json")
@click.argument("domain")
@click.option(
    "--from", "from_path", default=None, help="Chemin snapshot (ancien). Par défaut: avant-dernier"
)
@click.option("--to", "to_path", default=None, help="Chemin snapshot (récent). Par défaut: dernier")
@click.option("--md", is_flag=True, default=False, help="Sortie Markdown")
def cmd_diff_json(domain, from_path, to_path, md):
    """
    Diff entre 2 snapshots JSON (mode fichiers). Si --from/--to vides: compare N-1 vs N.
    """
    snaps = fs_list_snapshots(domain)
    if len(snaps) < 2 and (not from_path or not to_path):
        click.echo("Pas assez de snapshots. Utilise `recondns track <domain>` deux fois.")
        return

    def pick_path(path_or_idx: str | None) -> Path | None:
        if path_or_idx and Path(path_or_idx).exists():
            return Path(path_or_idx)
        return None

    from_snap = pick_path(from_path)
    to_snap = pick_path(to_path)

    # par défaut: avant-dernier vs dernier
    if not from_snap or not to_snap:
        snaps_sorted = sorted(snaps)
        # tu peux éventuellement ajouter une sécurité si len(snaps_sorted) < 2
        from_snap = from_snap or snaps_sorted[-2]
        to_snap = to_snap or snaps_sorted[-1]

    old = fs_load_snapshot(from_snap)
    new = fs_load_snapshot(to_snap)
    diff = diff_reports(old, new)

    if md:
        click.echo(render_diff_md(diff))
    else:
        # court résumé lisible
        add_n = len(diff.get("added", []))
        rm_n = len(diff.get("removed", []))
        tk_n = len(diff.get("takeover_changes", []))
        click.echo(f"Diff {domain}: +{add_n} / -{rm_n} / takeoverΔ={tk_n}")
        if add_n:
            click.echo(f"  added (ex): {diff['added'][:5]}")
        if rm_n:
            click.echo(f"  removed (ex): {diff['removed'][:5]}")
        if tk_n:
            click.echo(f"  takeover changes (ex): {diff['takeover_changes'][:2]}")
