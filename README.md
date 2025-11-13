# Recondns by guepster

**Outil CLI de reconnaissance DNS avancée**, orienté :

- 🌐 Enumeration passive (crt.sh, CertSpotter, BufferOver)
- 🔍 Bruteforce léger de sous-domaines
- 🛡️ Détection de subdomain takeover
- 🛰️ Enrichissement IP (ASN, pays, fournisseur Cloud)
- 🗄️ Snapshots versionnés (SQLite)
- 📊 Diff entre snapshots + rapport HTML

recondns = un mini “amass-lite” focalisé sur la surveillance DNS et la détection de changements.

##Info

# Résumé DNS + passif
recondns info example.com

# Résumé + bruteforce avec wordlist
recondns info example.com --wordlist wordlists/common.txt

# Avec détection de takeover filtrée sur un provider
recondns info example.com --check-takeover --provider-filter aws

##Snapshot

# Snapshot simple en JSON
recondns snapshot example.com

# Snapshot vers un fichier spécifique
recondns snapshot example.com -o data/example_snapshot.json

# Snapshot + historique SQLite
recondns snapshot example.com --db data/recondns.sqlite

---

# 🚀 Installation

```bash
python -m venv .venv
source .venv/bin/activate   # Windows : .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .


