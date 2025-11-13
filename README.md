# Recondns by guepster

_Avertissement légal

N’utilise cet outil que sur des domaines pour lesquels tu disposes d’une autorisation explicite, ou dans un cadre strictement éducatif/légal.
Toute utilisation abusive est sous la responsabilité de l’utilisateur._

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
Ce que ça affiche :
- Compteurs DNS (A / AAAA / NS / MX / TXT / CNAME)
- Nombre de sous-domaines trouvés (crt.sh + passif + bruteforce)
- Éventuels findings de subdomain takeover
- IP enrichment : ASN, pays, cloud (AWS / GCP / Azure /…)
- Mail security : MX, SPF, DMARC, DKIM (hint)

Options utiles :

- --no-crt : désactive crt.sh (plus rapide / plus discret)
- -r, --resolver : forcer un résolveur (ex: 1.1.1.1 ou 1.1.1.1,8.8.8.8)
- --wordlist : bruteforce léger de sous-domaines
- --bruteforce-depth : profondeur du bruteforce (par défaut 1)
- --check-takeover + --signatures + --provider-filter : takeover

## Résumé DNS + passif
recondns info example.com

## Résumé + bruteforce avec wordlist
recondns info example.com --wordlist wordlists/common.txt

## Avec détection de takeover filtrée sur un provider
recondns info example.com --check-takeover --provider-filter aws

---

# Snapshot complet : snapshot
_Contenu du JSON :
  - dns : enregistrements A/AAAA/NS/MX/TXT/CNAME
  - crt_subdomains : sous-domaines trouvés (passif + bruteforce)
  - crt_subdomains_resolved : sous-domaines résolus en A
  - takeover_checks : résultats des checks takeover
  - ip_enrichment : infos ASN / pays / cloud pour chaque IP
  - mail_security : MX / SPF / DMARC / DKIM (hint)_

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
_Le diff montre :
  - Diff DNS (ajouts / retraits par type)
  - Sous-domaines ajoutés / retirés
  - Changement sur les findings takeover_

## Diff console
recondns diff example.com --db data/recondns.sqlite --from 3 --to 7

## Diff + rapport HTML complet
recondns diff example.com --db data/recondns.sqlite --from 3 --to 7 --html diff_3_7.html

---

# Mode fichiers : track, timeline, diff-json
_Les snapshots JSON sont stockés dans : data/<domaine>/YYYYmmdd_HHMMSS[_{label}].json._

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
```


