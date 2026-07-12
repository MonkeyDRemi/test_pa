# 🛡 APSA — Static Analyzer

> Outil d'analyse de sécurité statique (SAST) multi-langages développé dans le cadre du Projet Annuel ESGI 2025-2026.

**Auteurs** : Ahmed BENSAID & Remi VAVICHANDRAN

---

## Présentation

APSA (Application de Pentest par Analyse Statique) détecte automatiquement les vulnérabilités de sécurité dans le code source **sans exécuter l'application**. Il supporte Python, JavaScript et PHP, et peut enrichir ses résultats avec des explications et corrections générées par **Gemini 2.5 Flash Lite**.

---

## Fonctionnalités

| Fonctionnalité | Détail |
|---|---|
| Analyse Python | AST natif — eval, exec, os.system, injections SQL, secrets hardcodés |
| Analyse JavaScript | Node.js — XSS, eval, injections SQL, open redirect, document.cookie |
| Analyse PHP | PHP CLI — injections SQL/commande/code, XSS, LFI/RFI, unserialize |
| Détection de secrets | Regex sur signatures connues — clés AWS, tokens GitHub, clés Google, Slack, Stripe, PEM |
| Scan de dépendances (SCA) | requirements.txt / package.json — CVE connues via l'API OSV.dev |
| Whitelist de faux positifs | Commentaire `# apsa-ignore` (ou `// apsa-ignore`) en fin de ligne |
| Dédoublonnage | Suppression automatique des findings strictement identiques |
| Scoring A→F | Score de criticité 0-100 pondéré par sévérité |
| Rapport HTML | Rapport visuel complet avec tableau et métriques |
| Rapport Markdown | Rapport exportable pour GitHub/GitLab |
| Analyse IA | Explication + code corrigé via Gemini 2.5 Flash Lite |
| CLI Typer | Interface ligne de commande complète avec aide intégrée |

---

## Prérequis

- Python 3.10+
- Node.js (pour l'analyse JavaScript)
- PHP CLI (pour l'analyse PHP)
- Dépendances Python : `rich`, `pyyaml`, `typer`

```bash
pip install rich pyyaml typer
```

---

## Installation

```bash
git clone <repo>
cd PA_2025-2026
pip install rich pyyaml typer
```

---

## Utilisation

### Scan basique (affichage terminal)
```bash
python main.py scan ./mon_projet
```

### Scan avec rapport HTML
```bash
python main.py scan ./mon_projet --report html --output rapport.html
```

### Scan avec rapport Markdown
```bash
python main.py scan ./mon_projet --report md --output rapport.md
```

### Scan avec analyse IA (Gemini)
```bash
python main.py scan ./mon_projet --report html --ai --gemini-key VOTRE_CLE_API
```

### Définir la clé API via variable d'environnement
```bash
export GEMINI_API_KEY="VOTRE_CLE_API"
python main.py scan ./mon_projet --ai
```

### Limiter le nombre d'appels IA
```bash
python main.py scan ./mon_projet --ai --gemini-key KEY --max-ai 5
```

### Désactiver le scan de dépendances (SCA) — utile hors ligne
```bash
python main.py scan ./mon_projet --no-sca
```

### Ignorer un faux positif directement dans le code
```python
eval(user_input)  # apsa-ignore
eval(user_input)  # apsa-ignore: PY_CODE_INJECTION_EVAL
```
Le marqueur `apsa-ignore` fonctionne quel que soit le style de commentaire
du langage (`#`, `//`, `/* */`). Sans précision de règle, il ignore tous
les findings de la ligne ; avec `: RULE_ID1,RULE_ID2`, seules ces règles
sont ignorées.

### Afficher les informations et l'aide
```bash
python main.py info
python main.py scan --help
```

---

## Structure du projet

```
PA_2025-2026/
├── main.py                    # CLI principal (Typer)
├── config.yaml                # Règles configurables
├── pyproject.toml             # Dépendances
├── README.md                  # Ce fichier
│
├── core/
│   ├── models.py              # Dataclass Vulnerability
│   ├── scorer.py              # Moteur de scoring (grades A→F)
│   ├── reporter.py            # Générateur HTML + Markdown
│   ├── ai_advisor.py          # Intégration Gemini 2.5 Flash Lite
│   ├── secrets_scanner.py     # Détection de secrets par regex (AWS, GitHub, PEM…)
│   ├── sca_scanner.py         # Scan de dépendances (SCA) via OSV.dev
│   ├── dedupe.py              # Dédoublonnage des findings
│   └── suppressions.py        # Whitelist via commentaires `apsa-ignore`
│
├── parsers/
│   ├── py_parser.py           # Analyseur Python (AST natif)
│   ├── js_parser.py           # Wrapper Python → Node.js
│   ├── js_scanner.js          # Analyseur JavaScript (Node.js)
│   ├── php_parser.py          # Wrapper Python → PHP CLI
│   └── php_scanner.php        # Analyseur PHP
│
├── tests/
│   ├── test_py_parser.py      # 12 tests — module Python
│   ├── test_scorer.py         # 6 tests — moteur de scoring
│   └── test_reporter.py       # 3 tests — générateur de rapports
│
└── tests_samples/
    ├── vulne.py               # Fichier Python avec vulnérabilités intentionnelles
    ├── vulne.js               # Fichier JavaScript avec vulnérabilités intentionnelles
    └── vulne.php              # Fichier PHP avec vulnérabilités intentionnelles
```

---

## Règles de détection

### Python
| Règle | Sévérité | Description |
|---|---|---|
| `PY_CODE_INJECTION_EVAL` | CRITICAL | Utilisation de `eval()` |
| `PY_CODE_INJECTION_EXEC` | CRITICAL | Utilisation de `exec()` |
| `PY_CMD_INJECTION_SYSTEM` | CRITICAL | Appel à `os.system()` |
| `PY_CMD_INJECTION_POPEN` | CRITICAL | Appel à `os.popen()` |
| `PY_CMD_INJECTION_RUN` | HIGH | Appel à `subprocess.run()` |
| `PY_SQL_INJECTION` | CRITICAL | Requête SQL construite dynamiquement |
| `PY_HARDCODED_SECRET` | HIGH | Secret/mot de passe codé en dur |

### JavaScript
| Règle | Sévérité | Description |
|---|---|---|
| `XSS_INNER_HTML` | HIGH | Affectation `.innerHTML` avec variable |
| `XSS_DOCUMENT_WRITE` | HIGH | `document.write()` avec variable |
| `CODE_INJECTION_EVAL` | CRITICAL | `eval()` détecté |
| `CODE_INJECTION_FUNCTION` | CRITICAL | `new Function()` détecté |
| `SQL_INJECTION_CONCAT` | CRITICAL | Concaténation dans une requête SQL |
| `SQL_INJECTION_TEMPLATE` | CRITICAL | Template literal dans une requête SQL |
| `OPEN_REDIRECT` | MEDIUM | `window.location` avec variable |

### PHP
| Règle | Sévérité | Description |
|---|---|---|
| `SQL_INJECTION_CONCAT` | CRITICAL | Concaténation dans une requête SQL |
| `XSS_ECHO_GET_POST` | CRITICAL | `echo` de `$_GET`/`$_POST` sans échappement |
| `CMD_INJECTION_EXEC` | CRITICAL | `system()`/`exec()` avec variable |
| `CODE_INJECTION_EVAL` | CRITICAL | `eval()` avec variable |
| `FILE_INCLUSION` | CRITICAL | `include`/`require` avec variable (LFI/RFI) |
| `UNSAFE_UNSERIALIZE` | CRITICAL | `unserialize()` sur entrée utilisateur |
| `HARDCODED_SECRET` | HIGH | Mot de passe codé en dur |
| `WEAK_HASH_MD5` | MEDIUM | `md5()` pour hacher un mot de passe |

### Secrets (tous langages, par signature)
| Règle | Sévérité | Description |
|---|---|---|
| `SECRET_AWS_ACCESS_KEY` | CRITICAL | Clé d'accès AWS (`AKIA…`/`ASIA…`) |
| `SECRET_AWS_SECRET_KEY` | CRITICAL | Clé secrète AWS |
| `SECRET_GITHUB_TOKEN` | CRITICAL | Token GitHub (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) |
| `SECRET_GOOGLE_API_KEY` | HIGH | Clé API Google (`AIza…`) |
| `SECRET_SLACK_TOKEN` | CRITICAL | Token Slack (`xox…`) |
| `SECRET_SLACK_WEBHOOK` | HIGH | URL de webhook Slack |
| `SECRET_STRIPE_KEY` | CRITICAL | Clé secrète Stripe (mode live) |
| `SECRET_PRIVATE_KEY_BLOCK` | CRITICAL | Bloc de clé privée PEM |
| `SECRET_GENERIC_JWT` | MEDIUM | Jeton JWT codé en dur |

### Dépendances (SCA)
| Règle | Sévérité | Description |
|---|---|---|
| `SCA_<ID_OSV>` | Variable (selon l'advisory) | CVE connue dans une dépendance `requirements.txt`/`package.json`, via [OSV.dev](https://osv.dev) |

---

## Scoring

| Score | Grade | Signification |
|---|---|---|
| 0 | A | Aucune vulnérabilité |
| 1–10 | B | Risque faible |
| 11–30 | C | Risque modéré |
| 31–60 | D | Risque élevé |
| 61–100 | F | Risque critique |

**Pondération :** CRITICAL = 25 pts · HIGH = 10 pts · MEDIUM = 4 pts · LOW = 1 pt

---

## Lancer les tests

```bash
python -m unittest discover tests/ -v
```

Résultat attendu : **21 tests, 0 erreurs**.

---

## Architecture technique

```
CLI (Typer)
    │
    ▼
main.py — Orchestre le scan
    │
    ├──► PythonScanner  (ast.NodeVisitor)
    ├──► JavaScriptScanner  (subprocess → Node.js)
    └──► PHPScanner  (subprocess → PHP CLI)
         │
         ▼
    [Vulnerability]  ──► Scorer ──► ScanScore (grade A→F)
                     ──► Reporter ──► HTML / Markdown
                     ──► AIAdvisor ──► Gemini API
```

---

## Obtenir une clé API Gemini

1. Aller sur [Google AI Studio](https://aistudio.google.com)
2. Créer un projet et générer une clé API
3. Utiliser avec `--gemini-key` ou la variable `GEMINI_API_KEY`

---

*APSA SAST — Ahmed BENSAID & Remi VAVICHANDRAN — ESGI 2025-2026*
#   t e s t _ p a  
 