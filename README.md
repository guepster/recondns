# Recondns by guepster

**Outil CLI de reconnaissance DNS avancée**, orienté :

- 🌐 Enumeration passive (crt.sh, CertSpotter, BufferOver)
- 🔍 Bruteforce léger de sous-domaines
- 🛡️ Détection de subdomain takeover
- 🛰️ Enrichissement IP (ASN, pays, fournisseur Cloud)
- 🗄️ Snapshots versionnés (SQLite)
- 📊 Diff entre snapshots + rapport HTML

recondns = un mini “amass-lite” focalisé sur la surveillance DNS et la détection de changements.

---

# Résumé rapide : info

## Résumé DNS + passif
recondns info example.com

## Résumé + bruteforce avec wordlist
recondns info example.com --wordlist wordlists/common.txt

## Avec détection de takeover filtrée sur un provider
recondns info example.com --check-takeover --provider-filter aws

---

# Snapshot complet : snapshot

## Snapshot simple en JSON
recondns snapshot example.com

## Snapshot vers un fichier spécifique
recondns snapshot example.com -o data/example_snapshot.json

## Snapshot + historique SQLite
recondns snapshot example.com --db data/recondns.sqlite

---

# Historique (SQLite) : history

## Liste simple
recondns history example.com --db data/recondns.sqlite

## Export Markdown
recondns history example.com --db data/recondns.sqlite --md --out history.md

---

# Diff (commande)

## Diff console
recondns diff example.com --db data/recondns.sqlite --from 3 --to 7

## Diff + rapport HTML complet
recondns diff example.com --db data/recondns.sqlite --from 3 --to 7 --html diff_3_7.html

---

# Mode fichiers : track, timeline, diff-json

## Scan et snapshot JSON local
recondns track example.com

## Voir la timeline locale
recondns timeline example.com

## Diff entre deux snapshots JSON (N-1 vs N par défaut) en Markdown
recondns diff-json example.com --md


---

# 🚀 Installation

```bash
python -m venv .venv
source .venv/bin/activate   # Windows : .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .

---

***Avertissement légal

N’utilise cet outil que sur des domaines pour lesquels tu disposes d’une autorisation explicite, ou dans un cadre strictement éducatif/légal.
Toute utilisation abusive est sous la responsabilité de l’utilisateur.***

