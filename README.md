# recondns-cli

Mini outil CLI pour la reconnaissance passive DNS + agrégation crt.sh — snapshot JSON.

## Installation rapide
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Usage
```bash
# snapshot et écriture auto
recondns snapshot example.com

# snapshot vers fichier précis
recondns snapshot example.com -o /tmp/example_snapshot.json

# résumé rapide
recondns info example.com
```

## Roadmap (features prochaines)
- Subdomain takeover checks
- Timeline / historique (snapshots dans SQLite)
- Risk scoring & prioritization
- Export STIX / integration SIEM

## Avertissement légal
Utiliser cet outil uniquement sur des domaines dont vous avez l'autorisation ou à des fins éducatives/legales. Toute utilisation abusive est de la responsabilité de l'utilisateur.
