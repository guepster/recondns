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

# 🚀 Installation

```bash
python -m venv .venv
source .venv/bin/activate   # Windows : .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
