# --- CLI / logging
import logging
import sys
from pathlib import Path
import click

# --- Mode "collecte"
from .core import snapshot_domain

# --- Export JSON brut (une photo du scan)
from .exporter import export_snapshot

# --- MODE DB (SQLite)
from .db import (
    init_db,
    save_snapshot as db_save_snapshot,
    list_snapshots as db_list_snapshots,
    get_snapshot_by_id,
)

from .diffing import diff_reports as db_diff_reports

# --- MODE FICHIERS (snapshots JSON)
from .storage import (
    save_snapshot as fs_save_snapshot,
    latest_snapshot as fs_latest_snapshot,
    list_snapshots as fs_list_snapshots,
    load_snapshot as fs_load_snapshot,
)

from .diffs import diff_snapshots as fs_diff_snapshots
from .report_md import render_diff_md as fs_render_diff_md

@click.group()
def main():
    """recondns — petit outil DNS + crt.sh (snapshot)"""
    pass

# ---------- SNAPSHOT ----------
@main.command()
@click.argument("domain")
@click.option("--out", "-o", default=None, help="Fichier de sortie JSON (si non précisé auto gen)")
@click.option("--no-crt", is_flag=True, default=False, help="Désactive l'appel vers crt.sh (rapide & safe)")
@click.option("--resolver", "-r", default=None, help="IP d'un résolveur DNS (ex: 1.1.1.1)")
@click.option("--resolve-limit", default=None, type=int, help="Limite le nb de sous-domaines CRT à résoudre (ex: 50)")
@click.option("--check-takeover", is_flag=True, default=False, help="Active la détection de Subdomain Takeover (lecture seule)")
@click.option("--signatures", default=None, help="Chemin vers un YAML de signatures (override par défaut)")
@click.option("--takeover-workers", default=8, type=int, help="Nombre de threads pour checks takeover (default 8)")
@click.option("--takeover-delay", default=0.2, type=float, help="Délai entre checks takeover (sec)")
@click.option("--takeover-verbose", is_flag=True, default=False, help="Mode verbeux pour takeover (logs)")
@click.option("--db", default=None, help="Chemin SQLite pour enregistrer l'historique (ex: data/recondns.sqlite)")
def snapshot(domain, out, no_crt, resolver, resolve_limit, check_takeover, signatures,
             takeover_workers, takeover_delay, takeover_verbose, db):
    """Prend un snapshot DNS + crt.sh pour DOMAIN et l'exporte en JSON (et DB si --db)."""
    if takeover_verbose:
        logging.getLogger("recondns").setLevel(logging.DEBUG)
    click.echo(f"[+] Snapshot pour {domain} ...")
    report = snapshot_domain(domain,
                             use_crt=(not no_crt),
                             resolver_ip=resolver,
                             resolve_limit=resolve_limit,
                             check_takeover=check_takeover,
                             signatures_path=signatures,
                             takeover_max_workers=takeover_workers,
                             takeover_delay=takeover_delay,
                             takeover_verbose=takeover_verbose)
    outfile = export_snapshot(report, out)
    click.echo(f"[+] Snapshot écrit : {outfile}")

    if db:
        init_db(db)
        snap_id = db_save_snapshot(db, report)
        click.echo(f"[+] Snapshot sauvegardé en DB ({db}) avec id={snap_id}")

# ---------- INFO ----------
@main.command()
@click.argument("domain")
@click.option("--no-crt", is_flag=True, default=False, help="Désactive l'appel vers crt.sh (rapide & safe)")
@click.option("--resolver", "-r", default=None, help="IP d'un résolveur DNS (ex: 1.1.1.1)")
@click.option("--resolve-limit", default=None, type=int, help="Limite le nb de sous-domaines CRT à résoudre (ex: 50)")
@click.option("--check-takeover", is_flag=True, default=False, help="Active la détection de Subdomain Takeover (lecture seule)")
@click.option("--signatures", default=None, help="Chemin vers un YAML de signatures (override par défaut)")
@click.option("--takeover-workers", default=8, type=int, help="Nombre de threads pour checks takeover (default 8)")
@click.option("--takeover-delay", default=0.2, type=float, help="Délai entre checks takeover (sec)")
@click.option("--takeover-verbose", is_flag=True, default=False, help="Mode verbeux pour takeover (logs)")
def info(domain, no_crt, resolver, resolve_limit, check_takeover, signatures,
         takeover_workers, takeover_delay, takeover_verbose):
    """Affiche un résumé en console (A / NS / MX counts)."""
    if takeover_verbose:
        logging.getLogger("recondns").setLevel(logging.DEBUG)
    report = snapshot_domain(domain,
                             use_crt=(not no_crt),
                             resolver_ip=resolver,
                             resolve_limit=resolve_limit,
                             check_takeover=check_takeover,
                             signatures_path=signatures,
                             takeover_max_workers=takeover_workers,
                             takeover_delay=takeover_delay,
                             takeover_verbose=takeover_verbose)
    dns = report.get("dns", {})
    click.echo(f"Domain: {domain}")
    for k in ["A", "AAAA", "NS", "MX", "TXT", "CNAME"]:
        click.echo(f" {k}: {len(dns.get(k, []))} entrées")
    click.echo(f"crt.sh sous-domaines trouvés: {len(report.get('crt_subdomains', []))}")
    if report.get("takeover_checks"):
        click.echo("Possible takeover findings:")
        for t in report.get("takeover_checks"):
            click.echo(f" - {t.get('host')} -> {t.get('provider')} ({t.get('method')}) [{t.get('scheme')} {t.get('status')}]")
    else:
        if check_takeover:
            click.echo("No takeover signatures found (checked).")

# ---------- HISTORY ----------
@main.command()
@click.argument("domain")
@click.option("--db", required=True, help="Chemin SQLite (ex: data/recondns.sqlite)")
@click.option("--limit", default=20, type=int, help="Nombre de snapshots à lister")
def history(domain, db, limit):
    """Liste les snapshots d'un DOMAIN sauvegardés dans la DB."""
    init_db(db)
    rows = db_list_snapshots(db, domain, limit)
    if not rows:
        click.echo("Aucun snapshot trouvé.")
        return
    click.echo(f"Snapshots pour {domain} (plus récents d'abord) :")
    for r in rows:
        click.echo(f" id={r['id']}  ts={r['ts']}")

# ---------- DIFF ----------
@main.command()
@click.argument("domain")
@click.option("--db", required=True, help="Chemin SQLite (ex: data/recondns.sqlite)")
@click.option("--from", "from_id", required=True, type=int, help="ID snapshot source")
@click.option("--to", "to_id", required=True, type=int, help="ID snapshot cible")
def diff(domain, db, from_id, to_id):
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
    d = db_diff_reports(a, b)

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
            click.echo(f" added:   {ad[:50]}{' ...' if len(ad)>50 else ''}")
        if rm:
            click.echo(f" removed: {rm[:50]}{' ...' if len(rm)>50 else ''}")
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
        resolver_ip=None,
        resolve_limit=resolve_limit,
        check_takeover=check_takeover,
        signatures_path=None,
        takeover_max_workers=8,
        takeover_delay=0.2,
        takeover_verbose=False,
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
@click.option("--from", "from_path", default=None, help="Chemin snapshot (ancien). Par défaut: avant-dernier")
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

    def pick(path_or_idx):
        if path_or_idx and Path(path_or_idx).exists():
            return Path(path_or_idx)
        return None

    A = pick(from_path)
    B = pick(to_path)

    # par défaut: avant-dernier vs dernier
    if not A or not B:
        snaps_sorted = sorted(snaps)
        A = A or snaps_sorted[-2]
        B = B or snaps_sorted[-1]

    old = fs_load_snapshot(A)
    new = fs_load_snapshot(B)
    diff = fs_diff_snapshots(old, new)

    if md:
        click.echo(fs_render_diff_md(diff))
    else:
        # court résumé lisible
        add_n = len(diff.get("added", []))
        rm_n  = len(diff.get("removed", []))
        tk_n  = len(diff.get("takeover_changes", []))
        click.echo(f"Diff {domain}: +{add_n} / -{rm_n} / takeoverΔ={tk_n}")
        if add_n:
            click.echo(f"  added (ex): {diff['added'][:5]}")
        if rm_n:
            click.echo(f"  removed (ex): {diff['removed'][:5]}")
        if tk_n:
            click.echo(f"  takeover changes (ex): {diff['takeover_changes'][:2]}")
