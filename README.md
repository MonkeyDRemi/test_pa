# Fiche de révision — APSA (Static Application Security Analyzer)

> Document de préparation à la soutenance. Objectif : pouvoir répondre à une question sur n'importe quel fichier du projet, pas seulement sur les grandes lignes.

---

## 1. Architecture générale

Le projet est organisé en **4 couches**, chacune ne connaissant que celle juste en dessous d'elle :

```
INTERFACES        CLI (main.py, Typer)        Interface Web (web_app.py, Flask)
                             \                        /
                              \                      /
CŒUR (core/)          scorer · reporter · dedupe · suppressions
                       secrets_scanner · sca_scanner · ai_advisor
                       rule_suggester · history
                             /          |          \
                            /           |           \
PARSERS            py_parser.py   js_parser.py    php_parser.py
                    (AST natif)   → js_scanner.js  → php_scanner.php
                                    (Node.js)         (PHP CLI)
                                       |                 |
SERVICES EXTERNES              OSV.dev (CVE)     Google Gemini (IA)
```

**Principe clé à savoir expliquer** : le Cœur ne sait jamais parser du code lui-même. Il délègue toujours aux parsers et ne manipule que des objets `Vulnerability` — un format **identique quel que soit le langage** (`file`, `line`, `column`, `rule_id`, `severity`, `description`). C'est ce contrat commun qui permet au scoring, aux rapports, au dédoublonnage, etc. de fonctionner sans jamais savoir si la faille vient de Python, JS, PHP, d'un secret ou d'une dépendance vulnérable — ils traitent tous des `Vulnerability` de la même façon.

**Flux d'un scan, dans l'ordre réel du code** (`_scan_directory`, dupliqué à l'identique dans `main.py` et `web_app.py`) :
1. Listing récursif des `.py` / `.js` / `.php` (`Path.rglob`)
2. Pour chaque `.py` : `ast.parse()` + `PythonScanner` + `scan_text_for_secrets()` sur le même contenu déjà lu
3. Pour chaque `.js` / `.php` : sous-processus (`node` / `php`) qui renvoie du JSON, **puis** relecture du fichier pour `scan_text_for_secrets()`
4. `scan_dependencies()` sur les `requirements.txt` / `package.json` trouvés (indépendant des étapes précédentes)
5. `dedupe_vulnerabilities()` — supprime les doublons exacts
6. `filter_suppressed()` — retire les lignes marquées `apsa-ignore`
7. `compute_score()` — calcule grade + score
8. (optionnel) `enrich_vulnerabilities()` et/ou `discover_all_findings()` — IA
9. Restitution : tableau CLI + `Panel` Rich, ou `results.html`, + sauvegarde dans `history.py`

---

## 2. Dossier `core/` — le cœur, indépendant de tout langage

### `models.py`
Une seule dataclass : `Vulnerability(file, line, column, rule_id, severity, description)`. C'est **le contrat** que respectent absolument tous les modules du projet — parsers, scanner de secrets, scanner SCA. Aucun champ optionnel : tout finding, peu importe sa source, doit remplir ces 6 champs.

### `scorer.py`
- `_WEIGHTS` : CRITICAL=25, HIGH=10, MEDIUM=4, LOW=1 — pondération arbitraire mais assumée (une CRITICAL "pèse" 25× plus qu'une LOW).
- `compute_score()` : somme les poids × occurrences, **plafonne à 100** (`min(raw, 100)`), puis mappe vers un grade :
  - 0 → A · ≤10 → B · ≤30 → C · ≤60 → D · au-delà → F
- Retourne un objet `ScanScore` (total, répartition par sévérité, score, grade, résumé texte).
- **Point à savoir défendre** : le score est plafonné à 100 même si la somme brute est plus grande (ex : 10 CRITICAL = 250 de brut → toujours 100/100 affiché). C'est voulu : au-delà d'un certain seuil, le grade F est déjà atteint, la précision du chiffre exact n'apporte plus rien.

### `reporter.py`
Deux fonctions : `generate_html()` et `generate_markdown()`. Génèrent un rapport **autonome** (le HTML embarque son propre CSS et un peu de JS pour déplier/replier les panneaux IA — pas de dépendance externe). Prennent en paramètre la liste de `Vulnerability`, le `ScanScore`, et optionnellement un dict `ai_advices` (rule_id → `AIAdvice`) pour enrichir chaque ligne d'un bouton "🤖 Voir analyse IA".

### `dedupe.py`
Une seule fonction, `dedupe_vulnerabilities()`. Clé de déduplication : `(file, line, rule_id, description)` — un `set` Python pour détecter les doublons stricts. Retourne `(liste_sans_doublons, nombre_supprimé)`.

### `suppressions.py`
Implémente le marqueur `apsa-ignore`. Regex : `apsa-ignore(?:\s*:\s*([A-Za-z0-9_,\s]+))?` — cherche juste ce texte dans la ligne brute, **peu importe la syntaxe de commentaire du langage** (`#`, `//`, peu importe, on ne cherche pas le symbole de commentaire lui-même). Deux cas :
- `# apsa-ignore` seul → ignore **toutes** les règles trouvées sur cette ligne
- `# apsa-ignore: RULE_ID1,RULE_ID2` → n'ignore que les règles listées
Un cache `_lines_cache` évite de relire un fichier plusieurs fois si plusieurs findings tombent dessus ; vidé à la fin de `filter_suppressed()`.

### `secrets_scanner.py`
`_SECRET_PATTERNS` : liste de 9 tuples `(rule_id, sévérité, regex, message)`. Détecte par **signature structurelle**, indépendamment du langage :
| Règle | Sévérité | Exemple de motif |
|---|---|---|
| `SECRET_AWS_ACCESS_KEY` | CRITICAL | `AKIA` / `ASIA` + 16 caractères |
| `SECRET_AWS_SECRET_KEY` | CRITICAL | `aws_secret_access_key = "..."` (40 car.) |
| `SECRET_GITHUB_TOKEN` | CRITICAL | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` |
| `SECRET_GOOGLE_API_KEY` | HIGH | `AIza` + 35 caractères |
| `SECRET_SLACK_TOKEN` | CRITICAL | `xoxb-`/`xoxp-`/... |
| `SECRET_SLACK_WEBHOOK` | HIGH | URL `hooks.slack.com/services/...` |
| `SECRET_STRIPE_KEY` | CRITICAL | `sk_live_...` |
| `SECRET_PRIVATE_KEY_BLOCK` | CRITICAL | `-----BEGIN ... PRIVATE KEY-----` |
| `SECRET_GENERIC_JWT` | MEDIUM | `eyJ...` (3 segments séparés par des points) |

`scan_text_for_secrets(filepath, content)` : boucle ligne par ligne (`content.splitlines()`), teste chaque pattern. Appelée pour **chaque fichier scanné**, en plus du parser dédié à son langage.

### `sca_scanner.py`
Le module le plus impliqué techniquement. Fonctionnement en **deux appels réseau successifs** (point important, souvent mal compris) :
1. `_query_osv_batch()` → `POST https://api.osv.dev/v1/querybatch` avec la liste des dépendances. **Cet endpoint ne renvoie QUE des IDs de vulnérabilité**, pas de détail.
2. `_fetch_vuln_details()` → `GET https://api.osv.dev/v1/vulns/{id}` pour chaque ID trouvé, afin d'avoir résumé et sévérité.

Parsing des manifestes :
- `_parse_requirements_txt()` : regex `^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)` — **ne traite que les pins exacts** (`django==3.1.0`). Une ligne `django>=3.0` ou `django` seul est **ignorée** (pas de version exacte à interroger).
- `_parse_package_json()` : lit `dependencies` + `devDependencies`, nettoie les préfixes `^`/`~` avec `re.sub(r"^[^\d]*", "", version)`.

`_severity_from_osv()` : si l'advisory OSV a un champ `database_specific.severity`, on le mappe (MODERATE→MEDIUM) ; **sinon HIGH par défaut** — choix assumé : une CVE connue sans sévérité précisée reste considérée comme un risque significatif plutôt que d'être sous-évaluée.

Toutes les requêtes réseau sont dans des `try/except` larges (`URLError`, `TimeoutError`, `OSError`, `ValueError`) qui retournent silencieusement un dict vide en cas d'échec — **le scan ne plante jamais** à cause d'OSV.dev indisponible.

### `ai_advisor.py`
Le plus gros fichier de `core/`. Deux modes bien distincts :

**Mode 1 — `get_advice()` / `enrich_vulnerabilities()`** : enrichit une vulnérabilité **déjà détectée**. Prompt système (`_SYSTEM_PROMPT`) demande un JSON à 3 clés : `explication`, `impact`, `fix`. `enrich_vulnerabilities()` déduplique par `rule_id` (un seul appel IA par règle, pas par occurrence) et attend `_DELAY_SECONDS = 4` secondes entre deux appels (throttling pour éviter le rate-limit de l'API).

**Mode 2 — `discover_findings()` / `discover_all_findings()`** : "recherche approfondie". Envoie le fichier **entier** à l'IA avec `_numbered_source()` qui préfixe chaque ligne de son vrai numéro (`   12| return token`) — ça évite que le modèle recompte les lignes lui-même et se trompe. Prompt (`_DISCOVERY_PROMPT`) demande de trouver des failles **logiques** (contrôle d'accès, IDOR, désérialisation...) hors de portée des règles statiques, et de fournir DEUX choses séparées :
- `suggested_fix` → code corrigé, montré à l'utilisateur
- `suggested_rule_id` / `suggested_rule_code` → à usage **interne admin uniquement**, jamais affiché à l'utilisateur final

`discover_all_findings()` plafonne à `max_files = 5` fichiers par défaut (coût/temps).

**Détails d'implémentation à connaître** :
- Le modèle utilisé dans le code est `"gemini-3.1-flash-lite"` (voir `client.models.generate_content(model=...)`). Les libellés affichés ailleurs (rapports, CLI) disent parfois "Gemini 2.5 Flash" — **incohérence de libellé à assumer si on te le fait remarquer**, le code source fait foi.
- `_get_client()` retourne `(None, message_erreur)` si `google-genai` n'est pas installé ou si `GOOGLE_API_KEY` n'est pas définie — jamais d'exception non gérée.
- `_strip_code_fence()` retire les ``` ```json ... ``` ``` que Gemini ajoute parfois malgré la consigne "réponds uniquement en JSON".

### `rule_suggester.py`
Écrit les pistes issues du mode découverte dans `new_rules/rules_{langage}.md` (un fichier par langage : `rules_py.md`, `rules_js.md`, `rules_php.md`, `rules_autre.md`). `save_rule_suggestion()` refuse d'écrire si `finding.error` est renseigné ou si `suggested_rule_code` est vide. Format volontairement minimal (décision explicite en cours de projet) : **titre (rule_id), date, description** — pas de nom de fichier scanné, pas de numéro de ligne, pas de code de règle affiché en clair dans le fichier, pour ne pas exposer d'informations sur le code des utilisateurs scannés dans ce journal.

### `history.py`
SQLite (`data/apsa_history.db`), une seule table `scans`. Colonnes clés : `scan_id` (PK), `session_id`, et plusieurs colonnes `*_json` qui stockent des listes/dicts sérialisés (`vulns_json`, `ai_advices_json`, `ai_findings_json`, `warnings_json`). `init_db()` fait aussi une micro-migration (`ALTER TABLE ... ADD COLUMN` si la colonne n'existe pas) pour rester compatible avec une base créée par une version antérieure du schéma.
**Toutes** les fonctions de lecture (`list_scans`, `get_scan`, `delete_scan`, `clear_history`) filtrent par `WHERE session_id = ?` — c'est le seul mécanisme d'isolation entre utilisateurs (pas de compte, pas de mot de passe).

---

## 3. Dossier `parsers/` — un binôme fichier Python + moteur par langage

### `py_parser.py`
Le seul vrai **AST natif**. `PythonScanner(ast.NodeVisitor)` avec deux méthodes de visite :
- `visit_Call()` : récupère le nom de la fonction appelée (`_get_func_name`, gère `ast.Name` et `ast.Attribute`), la compare à `_CRITICAL_FUNC_RULES` (dict de 10 fonctions → rule_id/sévérité : `eval`, `exec`, `compile`, `system`, `popen`, `subprocess`, `getoutput`, `call`, `run`, `Popen`) **et** à une liste additionnelle configurable via `config.yaml` (`rules.python.critical_functions`). Détecte aussi l'injection SQL : si le nom de fonction est dans `_SQL_SINKS = {"execute", "query", "executemany"}` et qu'un argument est un `ast.BinOp` (concaténation `+`) ou un `ast.JoinedStr` (f-string) → `PY_SQL_INJECTION`.
- `visit_Assign()` : si le nom de variable contient `password`/`passwd`/`secret`/`api_key`/`apikey`/`token` **et** que la valeur assignée est une constante string de plus de 3 caractères → `PY_HARDCODED_SECRET`. (C'est la détection "par nom de variable", différente et complémentaire de `secrets_scanner.py` qui détecte par **forme** du secret, peu importe le nom de la variable.)
- `self.generic_visit(node)` à la fin de chaque visite : indispensable pour continuer à descendre dans l'arbre (sinon seuls les nœuds de premier niveau seraient visités).

### `js_parser.py` + `js_scanner.js`
`js_parser.py` est un simple wrapper Python : `_find_node()` cherche `node` ou `nodejs` dans le PATH (`shutil.which`), lance `subprocess.run([node, js_scanner.js, filepath], timeout=30)`, parse le JSON retourné sur stdout en objets `Vulnerability`. Le `stderr` éventuel est capturé dans `self._stderr_msg` (affiché comme warning, ne fait pas planter le scan).

**`js_scanner.js` n'est PAS un vrai AST** — contrairement à ce qu'on pourrait dire vite en soutenance. C'est un moteur de règles **ligne par ligne, à base de regex**, avec des filtres additionnels (`filter`) pour réduire les faux positifs évidents (ex : `XSS_INNER_HTML` ignore la ligne si elle affecte une chaîne statique entre guillemets, pas une variable). 12 règles au total : XSS (`innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, `setAttribute` sur handler d'event), injection de code (`eval`, `new Function`, `setTimeout`/`setInterval` avec variable), injection SQL (concaténation ou template literal), `OPEN_REDIRECT`, et deux règles LOW sur `document.cookie` / `localStorage`. Ignore les lignes de commentaire (`//`, `*`, `/*`) avant de tester les règles. `validateSyntax()` utilise `vm.Script` pour vérifier que le fichier est au moins syntaxiquement valide (avertissement seul, ne bloque pas le scan).

### `php_parser.py` + `php_scanner.php`
Même schéma que JS : wrapper Python (`_find_php()` = `shutil.which("php")`) + moteur PHP en ligne de commande, **lui aussi à base de regex ligne par ligne**, pas d'AST PHP. 19 règles, plus riche que JS : injections SQL (3 variantes : concat, appel `query()`, `sprintf`), XSS (`echo`/`print` de superglobales, `echo` de variable sans `htmlspecialchars`), injection de commande (`exec`/`shell_exec`/... , backticks), injection de code (`eval`, `create_function` déprécié, `preg_replace` avec `/e`), inclusion de fichier (LFI/RFI), `unserialize()` sur entrée utilisateur (RCE), upload de fichier sans vérification MIME, open redirect, secrets codés en dur, hashs faibles (`md5`, `sha1`), et deux règles LOW sur l'exposition d'erreurs en production.
**Point à noter** : `PHPScanner.scan()` ne transmet **aucune configuration** au sous-processus PHP (contrairement à Python où `self.config` influence réellement `visit_Call`). La section `rules.php` de `config.yaml` existe mais **n'est pas branchée** dans le code actuel — un vrai développement futur serait de la faire lire par `php_scanner.php`.

---

## 4. Dossier `templates/` — l'interface web (Jinja2 + Flask)

- **`base.html`** : layout commun (variables CSS de couleurs, structure HTML partagée). Les autres templates en héritent.
- **`index.html`** : formulaire d'upload (drag & drop de fichiers), affiche si la clé Gemini est configurée côté serveur (`server_key_configured`), case à cocher "Activer l'analyse IA" et "Recherche approfondie". Contient un peu de JS côté client (`renderFiles()`) qui valide les extensions choisies avant d'activer le bouton de scan.
- **`results.html`** : affiche le tableau des vulnérabilités (triées par sévérité), les panneaux dépliables d'analyse IA, la section "recherche approfondie" (affiche `suggested_fix`, jamais `suggested_rule_code`), et les avertissements de scan (secrets/SCA/dédoublonnage/apsa-ignore comptés).
- **`history.html`** : liste des scans passés pour la session en cours, avec stats (`history_stats()` : nombre total, score moyen, tendance sur les 20 derniers scans).
- **`error.html`** : page 404 générique (ex : scan_id introuvable ou session expirée).

---

## 5. Dossier `tests/` — 40 tests unitaires (`unittest`, pas `pytest`)

| Fichier | Ce qu'il vérifie |
|---|---|
| `test_py_parser.py` | Détection AST : `eval`, `exec`, `os.system`, `Popen`, injection SQL (concat et f-string), secret codé en dur, absence de faux positif sur du code propre, valeur courte non flaggée |
| `test_scorer.py` | Pondération par sévérité, plafond à 100, grade A quand vide, cas d'un seul CRITICAL |
| `test_reporter.py` | Génération HTML/Markdown sans crash, même sur une liste vide |
| `test_dedupe.py` | Doublons exacts supprimés, findings différents (ligne, règle) conservés |
| `test_suppressions.py` | `apsa-ignore` bare vs scopé à une règle précise, comptage des ignorés |
| `test_secrets_scanner.py` | Détection AWS/GitHub/Google/PEM, absence de faux positif, bon numéro de ligne |
| `test_sca_scanner.py` | **Parsing uniquement** (`_parse_requirements_txt`, `_parse_package_json`), sans appel réseau réel — pour rester rapide et fiable en CI |

Aucun test sur `ai_advisor.py` ni `rule_suggester.py` : ce sont les seuls modules qui dépendent d'un appel réseau à un tiers (Gemini), donc pas couverts par la suite automatisée actuelle — **limite assumée à mentionner si demandé**.

## Dossier `tests_samples/`
Fichiers volontairement vulnérables (`vulne.py`, `vulne.js`, `vulne.php`, `requirements.txt` avec une lib à CVE connue) utilisés pour les démonstrations manuelles, pas dans la suite `unittest`.

## Dossier `data/` (généré au runtime)
Contient uniquement `apsa_history.db` (SQLite), créé automatiquement au premier scan par `history.init_db()`. Absent du dépôt Git initialement.

## Dossier `new_rules/` (généré au runtime)
Créé par `rule_suggester.py` (`NEW_RULES_DIR.mkdir(parents=True, exist_ok=True)`) dès qu'une première piste de règle est sauvegardée. N'existe pas tant que le mode "recherche approfondie" n'a jamais trouvé de faille logique.

---

## 6. Fichiers à la racine

### `config.yaml`
Très court, 6 lignes. **Seule** la section `rules.python.critical_functions` est réellement lue (par `py_parser.py`). La section `rules.php` (critical_functions, sql_sinks) existe mais n'est actuellement lue par aucun code — dette technique mineure assumée.

### `pyproject.toml`
Déclaration Poetry (`package-mode = false`, pas un vrai package distribuable). Dépendances déclarées : `rich`, `pyyaml`, `typer`, `flask`, `gunicorn`. **Absent de cette liste** : `google-genai` (installé séparément dans le `Dockerfile`) — incohérence mineure entre les deux fichiers.

### `Dockerfile`
Base `python:3.12-slim`, installe `nodejs` et `php-cli` au niveau système (nécessaires pour les scanners JS/PHP), installe les dépendances Python via `pip` directement (pas via Poetry), expose le port `10000`, démarre avec `gunicorn --bind 0.0.0.0:10000 --timeout 180 web_app:app` (serveur de production, pas le serveur de dev Flask).

### `README.md`
Documentation utilisateur : installation, usage CLI, tableau des règles de détection par langage, structure du projet.

### `web_app.py`
Le pendant web de `main.py`. Points structurants :
- `SERVER_GEMINI_KEY = os.environ.get("GOOGLE_API_KEY", "").strip()` — lue **une fois** au démarrage du process, jamais depuis une requête utilisateur.
- `_get_session_id()` : crée un UUID stocké dans `session["session_id"]` (cookie signé par `FLASK_SECRET`) au premier passage, `session.permanent = True` pour qu'il survive au-delà de la fermeture du navigateur.
- Routes : `/` (formulaire), `/scan` (POST, lance l'analyse), `/results/<scan_id>` (affiche — retombe sur l'historique SQLite si le scan n'est plus en mémoire, ex : après un redémarrage du serveur), `/download/<scan_id>/<fmt>` (régénère et sert le rapport HTML/MD), `/api/scan` (API JSON, sans session ni historique), `/history`, `/history/<id>/delete`, `/history/clear`.
- `_SCANS: dict` + `_SCANS_LOCK` : cache en mémoire des résultats de scan récents (évite de repasser par SQLite à chaque affichage), protégé par un `threading.Lock` car Gunicorn peut servir plusieurs requêtes en parallèle.
- Vérifie systématiquement `data.get("session_id") != session_id` avant de rendre un résultat → **empêche un utilisateur de voir le scan d'un autre** en devinant un `scan_id`.

---

## 7. `main.py` — le point d'entrée CLI, en détail

C'est le fichier à connaître **par cœur** — c'est probablement celui que le jury regardera en premier si une démo live est demandée.

### Structure générale
- `app = typer.Typer(...)` : une seule vraie commande, `scan`, plus une commande `info` (aide statique, affiche juste un panneau).
- `console = Console()` (Rich) : toute la sortie passe par lui, jamais de `print()` brut.

### `_load_config()`
Charge `config.yaml` en `utf-8-sig` (tolère un BOM ajouté par certains éditeurs Windows/PowerShell) ; retourne `{}` si le fichier n'existe pas (aucun crash si absent).

### `_scan_directory()`
Détaillé en section 1 (flux). À noter : utilise `rich.progress.Progress` avec un `SpinnerColumn` — la barre de progression est `transient=True` (disparaît une fois terminée, ne pollue pas la sortie finale).

### `_display_results()` / `_display_score()` / `_display_ai_advices()`
Fonctions d'affichage pur (aucune logique métier). `_display_results` trie par sévérité puis fichier puis ligne avant d'construire la `rich.table.Table`. Si la liste est vide, affiche un `Panel` vert "Aucune vulnérabilité détectée" plutôt qu'un tableau vide.

### La commande `scan()` — tous les paramètres, dans l'ordre de définition
| Option | Défaut | Rôle |
|---|---|---|
| `target` (positionnel) | — | dossier ou fichier à scanner |
| `--report` / `-r` | `None` | `html` ou `md` — génère un rapport si renseigné |
| `--output` / `-o` | `None` | chemin de sortie custom |
| `--ai` | `False` | active l'enrichissement IA (mode 1 uniquement, pas la découverte — la découverte n'est disponible que côté web) |
| `--gemini-key` | env `GEMINI_API_KEY` | clé Gemini pour la session CLI (⚠ nom de variable différent de `GOOGLE_API_KEY` utilisé côté web — incohérence à assumer) |
| `--max-ai` | `10` | nombre max de règles distinctes envoyées à l'IA |
| `--sca` / `--no-sca` | `True` | active/désactive le scan de dépendances |
| `--ignore-markers` / `--no-ignore-markers` | `True` | respecte ou ignore les `apsa-ignore` |
| `--config` / `-c` | `config.yaml` | chemin du fichier de config |
| `--no-banner` | `False` (caché) | masque la bannière ASCII (utilisé pour les tests automatisés / CI, où l'ASCII art n'a pas d'intérêt) |

### Logique d'exécution, dans l'ordre exact du code
1. Affiche la bannière (sauf `--no-banner`)
2. Vérifie que `target` existe sur le disque (`os.path.exists`), sinon `Exit(code=1)`
3. Charge la config
4. **Détecte le cas particulier** : présence de fichiers source vs présence de manifestes SCA seuls (`has_source_files`, `has_manifests`) — évite d'afficher un message d'erreur trompeur si le dossier ne contient qu'un `requirements.txt`
5. Lance `_scan_directory()` (Python/JS/PHP + secrets)
6. Si `sca=True`, lance `scan_dependencies()` séparément et étend `vulns`
7. `dedupe_vulnerabilities()` puis `filter_suppressed()` (dans cet ordre précis — dédoublonner avant de filtrer les ignorés, pas l'inverse)
8. Affiche le tableau + le score
9. Si `--ai`, importe `enrich_vulnerabilities` **localement** (import différé dans la fonction, pas en haut du fichier — évite de charger `google-genai` si l'option n'est jamais utilisée)
10. Si `--report`, génère le fichier demandé. **Piège de code repéré** : `ai_advices = advices` est dans un `try/except NameError` — si `--ai` n'a pas été passé, la variable `advices` n'existe jamais, d'où le `NameError` intentionnellement absorbé pour retomber sur `ai_advices = {}`.
11. **Code de sortie du process** : `1` si au moins une vulnérabilité CRITICAL ou HIGH, sinon `0` — pensé pour être exploitable dans un pipeline CI (`if apsa scan .; then ...`).

### `info()`
Commande secondaire, purement informative — affiche la bannière et un rappel des langages supportés et des commandes courantes. Aucune logique.

### `if __name__ == "__main__": app()`
Point d'entrée standard Typer — permet aussi bien `python main.py scan ...` que l'installation d'un exécutable `apsa` via un entry point Poetry (non configuré actuellement, mais possible).

---

## 8. Questions pièges probables, classées par fichier

- **"Votre scanner JS/PHP est-il un vrai AST comme Python ?"** → Non, assume-le : c'est un moteur de règles ligne par ligne à base de regex avec filtres contextuels. Le choix de l'AST natif n'était possible que pour Python (module `ast` intégré) ; pour JS/PHP il aurait fallu une dépendance externe (parser JS en Python, souvent fragile), on a préféré déléguer à l'écosystème natif de chaque langage.
- **"Le fichier `config.yaml` s'applique-t-il à tous les langages ?"** → Non, seule la section Python est branchée dans le code actuel (`py_parser.py` la lit) ; la section PHP existe mais n'est pas encore consommée par `php_scanner.php`.
- **"Que se passe-t-il si OSV.dev ou Gemini est indisponible ?"** → Le scan continue normalement : tous les appels réseau sont encapsulés dans des `try/except` larges qui retournent une liste/dict vide, jamais de crash.
- **"Comment évitez-vous qu'un utilisateur voie le scan d'un autre sur le site web ?"** → Comparaison stricte de `session_id` (cookie signé par `FLASK_SECRET`) avant de rendre tout résultat, en mémoire (`_SCANS`) comme en base (`history.py`).
- **"Pourquoi deux appels à l'API OSV.dev et pas un seul ?"** → L'endpoint batch (`/querybatch`) ne renvoie que des IDs de vulnérabilité, pas de détail ; il faut un second appel (`/vulns/{id}`) pour obtenir résumé et sévérité.
- **"Le nom du modèle IA affiché correspond-il exactement au modèle utilisé ?"** → Petite incohérence de libellé assumée : le code appelle `"gemini-3.1-flash-lite"`, certains textes affichés disent "Gemini 2.5 Flash" — le code source fait foi.
- **"Vos tests couvrent-ils le module IA ?"** → Non, volontairement : c'est le seul module qui dépend d'un appel réseau tiers payant/rate-limité, donc pas inclus dans la suite `unittest` automatisée.
