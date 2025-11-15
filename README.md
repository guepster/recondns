# RECONDNS by guepster — Documentation Technique

**Guide Technique Complet / Features / Flags / Data Model**

Version - V1.0

---

## Introduction

**RECONDNS** est un outil de reconnaissance DNS & Web avancé permettant de :

- 🌐 Découvrir les sous-domaines (OSINT + bruteforce)
- 🌍 Résoudre & enrichir chaque IP (ASN, pays, cloud...)
- 🔒 Scanner automatiquement HTTP/HTTPS (status, technologies, headers de sécurité)
- 🏢 Classifier automatiquement les environnements (prod, staging, dev...)
- 📧 Vérifier la posture mail (SPF, DKIM, DMARC)
- ⚠️ Détecter les risques de Subdomain Takeover
- 📊 Éditer un rapport complet : findings + next steps par équipe
- 🎯 Produire un Risk Score global

> Ce README est un manuel technique complet, destiné aux utilisateurs avancés.

---

## Architecture générale

```
src/recondns/
│
├── cli.py                    → CLI principale
├── core.py                   → Orchestration du scan & snapshot
├── passive.py                → Sources passives (OSINT)
├── resolver.py               → Résolutions DNS
├── bruteforce.py             → Bruteforce de sous-domaines
├── takeover.py               → Détection takeover
├── enrich.py                 → Enrichissement (ASN, pays, org, cloud)
├── mailer.py                 → SPF / DKIM / DMARC
├── webcam.py                 → Scan HTTP/HTTPS + headers
├── categ.py                  → Classification des sous-domaines
├── risk.py                   → Risk Score
└── recommendations.py        → Recommandations par équipe
```

---

## Fonctionnalités principales

### **Passive DNS Enumeration**

**Sources :**

| Source | Méthode | Notes |
|--------|---------|-------|
| crt.sh/crtq | API | Rapide & performant |
| HackerTarget | HTTP | Simple & efficace |
| BufferOver | DNS | Partiel, instable |

**Sortie :**

```json
{
  "passive_subdomains": ["subforward": "network_error"]
}
```

---

### **Résolution DNS complète**

**Types supportés :** A, AAAA, MX, NS, TXT, CNAME

**Contrôles :**

- Timeout custom
- Retries
- Résolveur custom (`--resolver`)
- Limite (`--resolve-limit`)

**Sortie :**

```json
{
  "dns_subdomain_resolved": {
    "sub1.example.com": ["1.1.1.1"],
    "sub2.example.com": ["ns1.example.com"]
  }
}
```

---

### **Bruteforce de sous-domaines**

**Options :**

```bash
--wordlist <wordlist.txt>
--bruteforce-depth 1
```

**Sortie :**

```json
{
  "bruteforce": {
    "found": ["admin.example.com", "dev.example.com"],
    "found_existing": false
  }
}
```

---

### **Classification automatique des sous-domaines**

**Catégories détectées :**

```
app, admin, auth, api,
mail, vpn, ftp,
dev, staging, preprod, recette,
cdn, static
```

**Sortie :**

```json
{
  "categorization": {
    "admin.example.com": ["admin"],
    "staging-api.example.com": ["staging", "api"]
  }
}
```

---

### **Enrichissement IP (WHOIS / ASN / Cloud)**

**Supports :**

- ASN
- Organisation
- Cloud provider
- Pays

**Exemple :**

```json
{
  "ip_enrichment": {
    "1.2.3.4": {
      "asn": "AS13335",
      "org": "Amazon AWS",
      "country": "US",
      "cloud": "AWS"
    }
  }
}
```

---

### **Posture mail (SPF, DKIM, DMARC)**

**Sortie :**

```json
{
  "mail_security": {
    "mx_hosts": ["example.com.mail.protection.outlook.com"],
    "spf": true,
    "has_dmarc": true,
    "has_dkim": false
  }
}
```

---

### **Web Scan (HTTP/HTTPS + Sécurité)**

**Activé via :**

```bash
--web-scan
```

**Tests effectués :**

- Port 80/443
- Status code
- Title extraction
- Tech detection (User-Agent + HTML)
- **Headers de sécurité :**
  - HSTS
  - CSP
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy

**Sortie :**

```json
{
  "web": {
    "hosts": {
      "admin.example.com": {
        "ports": {"80": "open", "443": "open"},
        "http": {
          "status": 200,
          "title": "Admin Panel",
          "tech": ["Apache", "PHP"],
          "security_headers": {
            "hsts": false,
            "content_security_policy": false
          }
        }
      }
    }
  }
}
```

---

### **Subdomain Takeover Detection**

**Activé via :**

```bash
--check-takeover
```

**Analyse :**

- CNAME patterns
- Réponses 404/403/400 suspectes
- Providers connus (GitHub, Heroku, Shopify, AWS S3...)

**Exemple :**

```json
{
  "host": "old.example.com",
  "provider": "github-pages",
  "method": "CNAME",
  "winner": 404
}
```

---

### **Findings automatiques**

**Exemples :**

- /!\ Mail protégé par SPF + DMARC
- /!\ Aucun HSTS détecté
- /!\ Multi-cloud détecté
- /!\ DKIM absent

---

### **Next Steps par équipe**

**Teams :**

- RED TEAM
- BLUE TEAM
- CLOUD TEAM
- MAIL TEAM
- DEV TEAM
- GOV TEAM

**Exemple :**

```bash
[ NEXT STEPS — RED TEAM ]
• Sous-domaines administratifs détectés : restreindre l'accès (VPN, MFA)
• Aucun takeover détecté : maintenir le monitoring périodique
```

---

### **Risk Score**

**Barème basé sur :**

- Surface DNS
- Takeover
- Posture mail
- Headers de sécurité
- Multi-cloud
- Multi-pays

**Exemple :**

```yaml
Global Score : 70 / 100
Medium       : Medium
```

---

## **Commandes CLI**

### Commande principale

```bash
ngme
```

```bash
recondns info <domain> [options]
```

### Liste complète des options

| Option | Description |
|--------|-------------|
| `--no-api` | Désactiver crt.sh |
| `--resolver <IP>` | Résolveur custom |
| `--timeout <float>` | Timeout |
| `--retries <N>` | Retries DNS |
| `--resolve-limit <N>` | Limit subdomains |
| `--check-takeover` | Activer takeover |
| `--signature-file <path>` | Signature takeover custom |
| `--takeover-workers <N>` | Threads takeover |
| `--takeover-delay <s>` | Delay |
| `--takeover-verbose` | Logs takeover |
| `--wordlist` | Bruteforce |
| `--bruteforce-depth <N>` | Profondeur bruteforce |
| `--out-file <path>` | Export JSON |
| `--provider-filter <X>` | Filtrer provider takeover |
| `--web-scan` | Activer scan HTTP/HTTPS |

---

## **Format JSON complet du rapport**

```json
{
  "domain": "example.com",
  "dns": {},
  "passive_subdomains": [],
  "dns_subdomain_resolved": {},
  "bruteforce": {},
  "categorization": {},
  "ip_enrichment": {},
  "asn": {},
  "hosts": {},
  "summary": {},
  "takeover": {},
  "risk_score": {},
  "findings": [],
  "next_steps": {
    "RED": [],
    "BLUE": [],
    "CLOUD": [],
    "MAIL": [],
    "DEV": [],
    "GOV": []
  }
}
```

---

## **Cas d'usage avancés**

### Audit complet

```bash
recondns info target.com --web-scan --check-takeover
```

### Export SIEM

```bash
recondns info company.com --out report.json
```

### Analyse sécurité Web

```bash
recondns info site.com --web-scan
```

---

## **Dev — Étendre RECONDNS**

### Ajouter une source passive

→ `passive.py`

### Ajouter une règle Next Steps

→ `recommendations.py`

### Ajouter un header de sécurité

→ `webcam.py`

### Ajouter un facteur au Risk Score

→ `risk.py`

---

## /!\ **Disclaimer** /!\

Cet outil est destiné **exclusivement** :

- aux audits autorisés
- à la recherche
- à la formation en sécurité

Toute utilisation non autorisée est strictement interdite.

---

## **Auteur**

**Guepster**  
Cybersecurity • OSINT • Recon Engineering

GitHub : https://github.com/guepster »

---

**RECONDNS by guepster — Reconnaissance DNS & Web pour audits de sécurité avancés**
