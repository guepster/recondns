# RECONDNS

> Reconnaissance DNS & Web orientée **équipe** (Red / Blue / Cloud / Mail / Dev / Gov), avec snapshots, diff et console interactive.

---

## TL;DR

```bash
# Scan rapide (DNS + passif + bruteforce léger + mail)
recondns info example.com

# Scan complet avec web scan + scoring + recommandations
recondns info example.com --web-scan --check-takeover

# Prendre un snapshot versionné (JSON + DB)
recondns snapshot example.com --db data/recondns.sqlite --web-scan

# Voir l'historique d'un domaine
recondns history example.com --db data/recondns.sqlite

# Diff entre 2 snapshots DB
recondns diff example.com --db data/recondns.sqlite --from 1 --to 5 --html diff_example.html

# Mode fichiers (track dans ./data/)
recondns track example.com
recondns timeline example.com
recondns diff-json example.com --md
````

---

## Features principales

* **Découverte DNS complète**

  * A / AAAA / NS / MX / TXT / CNAME
  * Sous-domaines via CRT + passif + bruteforce
* **Recon Web intégrée (`--web-scan`)**

  * HTTP/HTTPS, ports ouverts, codes HTTP, titres, tech stack
  * Headers de sécurité : HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
* **Détection de sous-domain takeover**

  * Patterns SaaS / PaaS configurables via YAML
  * Filtrage par provider (`--provider-filter`)
* **Enrichissement IP**

  * Pays, ASN, organisation, cloud provider (AWS / Azure / OVH / …)
  * Vue “Providers / Hosting”
* **Posture mail**

  * MX, SPF, DMARC, hint DKIM
* **Scoring de risque**

  * Score global 0–100
  * Niveau Low / Medium / High
  * Vue “Quick risk view”
* **Recommandations par équipe**

  * RED TEAM / BLUE TEAM / CLOUD TEAM / MAIL TEAM / DEV TEAM / GOV TEAM
  * Concrètes, directement actionnables
* **Snapshots & historique**

  * Mode **DB** (SQLite) : `snapshot`, `history`, `diff`
  * Mode **fichiers** (`./data/<domain>/…`) : `track`, `timeline`, `diff-json`
* **Diff multi-couches**

  * DNS, sous-domaines, takeover, etc.
  * Sortie console, Markdown ou HTML complet
* **Console interactive**

  * `recondns` ou `recondns console`
  * Pour enchaîner les commandes sans retaper `recondns` à chaque fois

---

## Installation

### 1. Cloner le repo

```bash
git clone https://github.com/<ton-user>/recondns.git
cd recondns
```

### 2. Créer un venv & installer

```bash
python -m venv .venv
source .venv/bin/activate   # sous Linux/Mac
# .venv\Scripts\activate    # sous Windows

pip install -e .
```

Tu obtiens ensuite la commande :

```bash
recondns
```

---

## Architecture générale

RECONDNS repose sur quelques blocs principaux :

* `core.py` : fonction centrale `snapshot_domain()`
* `cli.py` : toutes les commandes CLI (info, snapshot, history, diff, track, ...)
* `storage.py` : gestion des snapshots JSON sur disque
* `db.py` : stockage et lecture des snapshots en SQLite
* `diffs.py` : calcul des différences entre deux rapports
* `exporter.py` : logique pour nommer et écrire les fichiers de snapshot
* `report_md.py` : rendu Markdown pour les diff JSON
* `recommendations.py` : génère les “Next steps” par équipe

---

## Commandes & usage détaillé

### 1. `info` — vue complète en console

```bash
recondns info <domain> [options]
```

**But :**
Prendre un snapshot complet **en mémoire** et afficher un rapport riche directement dans la console.

Exemple :

```bash
recondns info esgi.fr --web-scan --check-takeover
```

Sections affichées :

* `[ TARGET ]` : domaine
* `[ SURFACE SUMMARY ]`

  * nb de sous-domaines, IP uniques, ASN, pays, clouds publics
* `[ DNS SUMMARY ]`

  * A / AAAA / NS / MX / TXT / CNAME + nb de sous-domaines CRT
* `[ SUBDOMAINS ]`

  * liste dedupée CRT + passif + bruteforce
* `[ PASSIVE SOURCES ]`

  * quelles sources ont marché, lesquelles ont échoué (ex: bufferover: network_error)
* `[ HIGH-VALUE SUBDOMAINS ]`

  * tags : `admin`, `api`, `auth`, `remote`, …
* `[ DEV / TEST / RECETTE ]`

  * staging, preprod, sandbox, test, beta…
* `[ IP ENRICHMENT ]`

  * IP → pays, ASN, organisation, cloud
* `[ PROVIDERS / HOSTING ]`

  * regroupement par (ASN / Org / Cloud) + liste de quelques sous-domaines
* `[ WEB DETAILS ]` *(si `--web-scan`)*

  * host → code HTTP, titre page, techno (Apache, nginx, Netlify, wordpress, …)
* `[ WEB SUMMARY ]` *(si `--web-scan`)*

  * nb d’hôtes testés / répondants
  * ports 80/443 ouverts
  * HTTP only / HTTPS only / HTTP+HTTPS
  * stats headers de sécurité
  * vue fonctionnelle : hôtes admin / staging
* `[ MAIL SECURITY ]`

  * MX hosts
  * SPF / DMARC / DKIM (hint)
* `[ FINDINGS ]`

  * résumé des points forts / faibles
* `[ NEXT STEPS — <TEAM> TEAM ]`

  * recommandations ciblées (RED/BLUE/CLOUD/MAIL/DEV/GOV)
* `[ RISK SCORE ]`

  * score global 0–100 + niveau
* `[ QUICK RISK VIEW ]`

  * surface DNS, posture mail, DKIM

#### Options principales

* **Sources & DNS**

  * `--no-crt` : ne pas appeler crt.sh (plus rapide, plus safe)
  * `--resolver / -r` : IP d’un résolveur custom (ex: `1.1.1.1`)
  * `--timeout` : timeout DNS (sec)
  * `--retries` : nb de retries
  * `--resolve-limit` : limite le nb de sous-domaines à résoudre
* **Bruteforce**

  * `--wordlist` : wordlist de sous-domaines
  * `--bruteforce-depth` : profondeur (par défaut 1)
* **Takeover**

  * `--check-takeover` : active la détection de takeover
  * `--signatures` : YAML custom de signatures takeover
  * `--takeover-workers` : nb de threads
  * `--takeover-delay` : délai entre checks
  * `--takeover-verbose` : logs verbeux takeover
  * `--provider-filter` : filtrer par provider (ex : `--provider-filter heroku`)
* **Web**

  * `--web-scan` : active le scan HTTP/HTTPS
* **Sortie**

  * `--minimal` : vue très condensée (DNS/Mail/Surface)
  * `--out` : sauvegarde le rapport brut en JSON

Exemple minimal :

```bash
recondns info esgi.fr --minimal
```

---

### 2. `snapshot` — snapshot versionné (fichiers + DB)

```bash
recondns snapshot <domain> [options]
```

**But :**
Prendre un snapshot complet et **l’enregistrer** pour historique :

* en JSON (fichier)
* et/ou dans une DB SQLite (`--db`)

Exemple simple :

```bash
recondns snapshot esgi.fr --web-scan
```

Exemple avec DB :

```bash
recondns snapshot esgi.fr \
  --web-scan \
  --db data/recondns.sqlite
```

Ce que fait la commande :

1. Appelle `snapshot_domain()` avec les mêmes options que `info`
2. Appelle `export_snapshot(report, out)` pour écrire un JSON :

   * soit dans le fichier spécifié via `--out`
   * soit avec un nom auto (ex : `data/esgi.fr/20251115_203000.json`)
3. Si `--db` est fourni :

   * initialisation de la DB (`init_db`)
   * `db_save_snapshot()` → insert du snapshot (domaine, timestamp, JSON complet)
4. Si `--minimal`, affiche un résumé rapide :

   * DNS : A / AAAA / MX / NS / TXT
   * Mail : SPF / DMARC / DKIM
   * Surface : subs / resolved / IPs
   * Statut des sources passives (crt.sh, bufferover, etc.)

Options techniques identiques à `info` + :

* `--out / -o` : chemin de sortie JSON
* `--db` : fichier SQLite
* `--minimal` : résumé console

---

### 3. `history` — historique des snapshots (mode DB)

```bash
recondns history <domain> --db data/recondns.sqlite [options]
```

**But :**
Lister les snapshots disponibles pour un domaine dans une DB SQLite.

Exemple :

```bash
recondns history esgi.fr --db data/recondns.sqlite
```

Sortie texte classique :

```text
Snapshots pour esgi.fr (plus récents d'abord) :
 id=5  ts=2025-11-15T20:30:00
 id=4  ts=2025-11-14T18:22:11
 id=3  ts=2025-11-10T10:05:47
 ...
```

Options :

* `--limit` : nb de snapshots à lister (par défaut 20)
* `--md` : sortie au format Markdown
* `--out <file.md>` : écrit le Markdown dans un fichier

Exemple Markdown :

```bash
recondns history esgi.fr --db data/recondns.sqlite --md --out history_esgi.md
```

Génère :

```markdown
# Historique des snapshots — esgi.fr

| id | timestamp           | domaine |
|----|---------------------|---------|
| 5  | 2025-11-15T20:30:00 | esgi.fr |
| 4  | 2025-11-14T18:22:11 | esgi.fr |
| 3  | 2025-11-10T10:05:47 | esgi.fr |
```

---

### 4. `diff` — diff entre deux snapshots (mode DB)

```bash
recondns diff <domain> \
  --db data/recondns.sqlite \
  --from <id_source> \
  --to <id_cible> \
  [--html diff.html]
```

**But :**
Comparer deux snapshots en DB (par ID) pour le même domaine.

Exemple :

```bash
recondns diff esgi.fr \
  --db data/recondns.sqlite \
  --from 3 \
  --to 5 \
  --html diff_esgi_3_5.html
```

* Vérifie que les deux snapshots existent et correspondent au même domaine
* Utilise `diff_reports(a, b)` pour calculer les différences
* Affiche dans la console :

  * `[DNS]` : entrées ajoutées / supprimées
  * `[CRT Subdomains]` : sous-domaines ajoutés / supprimés
  * `[Takeover]` : nouveaux takeovers potentiels / supprimés
* Si `--html` :

  * Rend un rapport HTML via `diff_to_html()` et l’écrit sur disque

Exemple de sortie console :

```text
Diff esgi.fr  2025-11-10T10:05:47  →  2025-11-15T20:30:00

[DNS]
 A added:   ['203.0.113.42']
 MX removed: ['old-mx.example.com.']

[CRT Subdomains]
 added:   ['staging-refonte.esgi.fr', 'www.staging-refonte.esgi.fr']
 removed: ['old-preprod.esgi.fr']

[Takeover]
 added:   [{'host': 'blog.esgi.fr', 'provider': 'github-pages', ...}]
 removed: []
```

---

### 5. Mode fichiers : `track`, `timeline`, `diff-json`

Ce mode ne nécessite **pas de DB**. Tout est stocké dans `./data/<domain>/`.

#### `track` — prendre un snapshot JSON local

```bash
recondns track <domain> [--resolve-limit N] [--check-takeover] [--label LABEL]
```

* Utilise `snapshot_domain()` avec :

  * `use_crt=True`
  * résolveur système
  * bruteforce léger
* Sauvegarde le snapshot dans :

```text
data/<domain>/YYYYmmdd_HHMMSS[_label].json
```

Exemple :

```bash
recondns track esgi.fr --check-takeover --label preprod
# -> data/esgi.fr/20251115_203000_preprod.json
```

#### `timeline` — lister les snapshots locaux

```bash
recondns timeline <domain>
```

Exemple :

```text
20251110_100547.json
20251112_183011.json
20251115_203000_preprod.json
```

#### `diff-json` — diff entre deux snapshots JSON

```bash
recondns diff-json <domain> [--from path] [--to path] [--md]
```

Comportement :

* Si `--from` et `--to` ne sont **pas** fournis :

  * liste les snapshots (`fs_list_snapshots`)
  * compare **avant-dernier** vs **dernier**
* Sinon :

  * charge les chemins fournis s’ils existent

Deux modes de sortie :

* Sans `--md` : résumé console

  ```text
  Diff esgi.fr: +3 / -1 / takeoverΔ=1
    added (ex): ['staging-refonte.esgi.fr', 'www.staging-refonte.esgi.fr', 'beta.esgi.fr']
    removed (ex): ['old-preprod.esgi.fr']
    takeover changes (ex): [{'host': 'blog.esgi.fr', ...}]
  ```

* Avec `--md` : rapport complet Markdown via `render_diff_md(diff)`

---

### 6. Console interactive

```bash
# Deux façons équivalentes
recondns
recondns console
```

Lance une console type `cmd` avec des commandes internes :

* `info esgi.fr --web-scan`
* `snapshot esgi.fr --db data/recondns.sqlite`
* `history esgi.fr --db data/recondns.sqlite`
* `diff esgi.fr --db ... --from ... --to ...`
* `track esgi.fr`
* `timeline esgi.fr`
* `diff-json esgi.fr --md`
* etc.

Pratique pour enchaîner les analyses sans retaper `recondns` à chaque fois.

---

## Modèle de risque

Le score est calculé par `compute_risk_score()` à partir de :

* **Surface DNS** (`total_subdomains`)

  * > 200 sous-domaines → pénalité forte
  * > 50 sous-domaines → pénalité moyenne
  * > 10 sous-domaines → petite pénalité
* **Complexité cloud** (`clouds`)

  * > 2 clouds publics → forte pénalité
  * 2 clouds → pénalité moyenne
  * 1 cloud → petite pénalité
* **Posture mail** (`mail_sec`)

  * SPF absent → -10
  * DMARC absent → -10
  * DKIM hint absent → -5
* **Takeovers potentiels** (`takeover_count`)

  * > 0 → -20

Niveaux :

* `score >= 80` → **Low**
* `50 <= score < 80` → **Medium**
* `< 50` → **High**

---

## Catégorisation des sous-domaines

La fonction `categorize_subdomain()` applique des tags en fonction du nom :

* **Environnements non-prod** (`dev`)

  * `dev.`, `.dev.`, `-dev.`
  * `test.`, `recette.`, `preprod.`, `staging.`, `sandbox.`, `beta.`, …
* **Endpoints sensibles**

  * `admin`, `panel`, `backoffice` → `admin`
  * `api.` → `api`
  * `auth.`, `login.`, `sso.`, `idp.` → `auth`
  * `vpn.`, `remote.`, `rdp.`, `gateway.` → `remote`

Ces tags sont ensuite utilisés pour :

* `[ HIGH-VALUE SUBDOMAINS ]`
* `[ DEV / TEST / RECETTE ]`
* tri dans `[ WEB DETAILS ]`
* stats fonctionnelles dans `[ WEB SUMMARY ]`

---

## Usage responsable

RECONDNS est un outil de **reconnaissance**.
Tu es responsable de l’usage que tu en fais.

* Ne scanne que :

  * des domaines **que tu possèdes**,
  * ou pour lesquels tu as une **autorisation explicite** (pentest / bug bounty / mission).
* Respecte les lois locales (cybercriminalité, RGPD, etc.).
* Les fonctionnalités de takeover sont en lecture seule, mais restent sensibles.

---

## 🗺 Positionnement par rapport aux outils classiques

RECONDNS ne cherche pas à remplacer Amass/Subfinder/etc., mais à proposer :

* une **vue synthétique** prête à l’emploi pour :

  * RSSI, SecOps, Cloud, Dev, Gouvernance
* un **langage orienté équipes** :

  * sections `NEXT STEPS — <TEAM> TEAM`
* un **pipeline complet** :

  * découverte → enrichissement → scoring → recommandations → snapshots → diff

---

## Statut de la version

Cette version correspond à la **V1 publique** avec :

* `info` (avec `--web-scan`, takeover, scoring, recommandations)
* `snapshot` (JSON + SQLite)
* `history` (texte + Markdown)
* `diff` (DB, console + HTML)
* `track`, `timeline`, `diff-json` (mode fichiers)
* console interactive

Les évolutions possibles (roadmap perso) :

* plus de sources passives
* détection avancée de technologies
* scoring HSTS/CSP plus granularisé
* export JSON standardisé (ex: pour ingestion SIEM)

---

## Crédits / Contribuer

* Conception & dev : **Guepster / RECONDNS**
* Feedbacks, bug reports et idées bienvenus via issues / PR.

```bash
# Lancer les tests (si tu en ajoutes)
pytest
```

Si tu veux proposer une nouvelle feature :

1. Ouvre une issue avec :

   * description fonctionnelle
   * exemple de sortie souhaitée
2. Propose une PR propre (type : `feat:`, `fix:`, etc.)

---

**Bon recon.** 🛰
